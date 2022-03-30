/*
 * Copyright 2018-2019 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifdef __linux__
// usleep
#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#define isatty _isatty
#ifndef STDIN_FILENO
#define STDIN_FILENO _fileno(stdin)
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO _fileno(stdout)
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO _fileno(stderr)
#endif
#ifndef USELINENOISE
#define USELINENOISE 0
#endif
#else
#include <termios.h>
#include <unistd.h>
#ifndef USELINENOISE
#define USELINENOISE 1
#endif
#endif

#ifdef OPA_MBEDTLS
#include "mbedtls/version.h"
#endif
#if defined(OPA_MBEDTLS) || defined(OPABIGINT_USE_MBED)
#include "mbedtls/platform.h"
#endif

#if USELINENOISE
#include "linenoise.h"
#endif

#if defined(OPADBG) && defined(OPAMALLOC)
#include "opamalloc.h"
#endif

#include "opabuff.h"
#include "opac.h"
#include "opacore.h"
#include "oparb.h"
#include "opaso.h"
#include "opasock.h"
#include "licenses.h"
#include "winutils.h"

#ifdef OPA_OPENSSL
#include "opatls/openssl.h"
#endif
#ifdef OPA_MBEDTLS
#include "opatls/mbed.h"
#endif
#include "opatls/opatls.h"
#include "opatls/tlsutils.h"


#ifndef OPACLI_VERSION
#define OPACLI_VERSION 0.0.0-dev
#endif

#define STR_ERROR "ERROR: "
#define DEFAULT_HOST "localhost"

// TODO: this error code will be changing
#define ERR_AUTHREQ -53

#define PPXSTR(a) PPSTR(a)
#define PPSTR(a) #a


typedef struct {
	opasock s;
	char useTls;
	char needsClosed;
	char connectedOnce;
	opatlsState tls;
	opac client;
	char* authpass; // stores password when AUTH succeeds
} opacliClient;

typedef struct {
	const char* host;
	const char* sni;
	const char* pass; // password provided on command line
	uint16_t port;
	char useTLS;
	char istty;
	char printStatus;
	char authp;
	opatlsConfig* tlscfg;
} opacliConnectOptions;




static unsigned int argtouir(const char* s, unsigned int min, unsigned int max, const char* argname) {
	unsigned long v = strtoul(s, NULL, 0);
	if (v < min || v > max || (v == ULONG_MAX && errno == ERANGE)) {
		OPALOGERRF("arg \"%s\" out of range", argname);
		exit(EXIT_FAILURE);
	}
	return v;
}

static void printUsage(const char* bin, int exitCode) {
	opa_printf("Usage: %s [OPTIONS] [cmd [arg [arg ...]]]\n"
			"Options:\n"
			" -h <hostname>   server hostname (default " DEFAULT_HOST ")\n"
			" -p <port>       server port (default 4567)\n"
			" -a <password>   password for AUTH\n"
			" -r <repeat>     run specified command <repeat> times\n"
			" -i <interval>   when -r is used, wait <interval> seconds per command;\n"
			"                 can use decimal format: -i 0.01\n"
			" -x              read last argument from STDIN\n"
			" --indent <str>  indent when printing multiline response (default 4 spaces)\n"
			" --authp         prompt for AUTH password\n"
			" --sni <host>    server name expected when using TLS\n"
			" --cacert <file> file containing trusted CA certs for TLS\n"
			" --cert <file>   client's certificate for TLS (PEM format)\n"
			" --key <file>    client's private key for TLS (PEM format)\n"
			" --no-tls        disable TLS\n"
			" --tls-always    always use TLS (even for localhost)\n"
			" --help          print this help and exit\n"
			" --version       print version and exit\n"
			" --licenses      print the licenses of included software\n"
			, bin);
	exit(exitCode);
}

static int opaGetLine2(FILE* f, opabuff* b) {
	int err = opabuffSetLen(b, 0);
	while (!err) {
		int ch = fgetc(f);
		if (ch == EOF) {
			if (ferror(f)) {
				LOGSYSERRNO();
				err = OPA_ERR_INTERNAL;
			}
			break;
		}
		if (ch == '\n') {
			// do not include \n char at end of buffer
			err = opabuffAppend1(b, 0);
			break;
		}
		err = opabuffAppend1(b, ch);
	}
	return err;
}

#ifdef _WIN32
static void opacliWsaStartup(void) {
	WSADATA wsd;
	int wsaerr = WSAStartup(MAKEWORD(2, 2), &wsd);
	if (wsaerr) {
		LOGWINERRCODE(wsaerr);
		exit(EXIT_FAILURE);
	}
}

static int opaGetLineWinConsole(HANDLE h, opabuff* b) {
	int err = 0;
	opabuff wbuff;
	opabuffInit(&wbuff, b->flags & OPABUFF_F_ZERO);
	while (!err) {
		DWORD numRead = 0;
		err = opabuffAppend(&wbuff, NULL, sizeof(wchar_t));
		// note: ReadConsoleW is used because fgetwc has odd behavior when compiled on mingw-64 vs msvc. When
		//  compiled with mingw-64, fgetwc may return an extra newline character (does on win10; doesn't on win2k).
		//  Also, fgetwc does not seem to work right when trying to read unicode chars on win2k.
		//  In general, fgetwc seems buggy and inconsistent.
		if (!err) {
			wchar_t* wstr = (wchar_t*) wbuff.data;
			size_t wlen = opabuffGetLen(&wbuff) / sizeof(wchar_t);
			if (!err && !ReadConsoleW(h, wstr + wlen - 1, 1, &numRead, NULL)) {
				LOGWINERR();
				err = OPA_ERR_INTERNAL;
			}
			if (!err && numRead == 0) {
				OPALOGERR("Read 0 in ReadConsoleW()");
				err = OPA_ERR_INTERNAL;
			}
			if (!err && wlen > 0 && wstr[wlen - 1] == '\n') {
				char* utf8Str = NULL;
				wstr[wlen - 1] = 0;
				if (wlen > 1 && wstr[wlen - 2] == '\r') {
					wstr[wlen - 2] = 0;
				}
				err = winWideToUtf8(wstr, &utf8Str);
				if (!err) {
					opabuffFree(b);
					b->data = (uint8_t*) utf8Str;
					b->len = strlen(utf8Str) + 1;
					b->cap = b->len;
				}
				break;
			}
		}
	}
	opabuffFree(&wbuff);
	return err;
}

static int opaGetLine(FILE* f, opabuff* b) {
	if (isatty(_fileno(f))) {
		intptr_t inth = _get_osfhandle(_fileno(f));
		return opaGetLineWinConsole((HANDLE) inth, b);
	} else {
		return opaGetLine2(f, b);
	}
}

#else

static int opaGetLine(FILE* f, opabuff* b) {
	return opaGetLine2(f, b);
}

#endif

static size_t opacliReadCB(opac* c, void* buff, size_t len) {
	size_t tot;
	int err = 0;
	opacliClient* cli = list_entry(c, opacliClient, client);
	if (cli->useTls) {
		err = opatlsStateRead(&cli->tls, buff, len, &tot);
	} else {
		err = opasockRecv(&cli->s, buff, len, &tot);
	}
	if (err && err != OPA_ERR_WOULDBLOCK) {
		cli->needsClosed = 1;
	}
	return tot;
}

static size_t opacliWriteCB(opac* c, const void* buff, size_t len) {
	size_t tot;
	int err = 0;
	opacliClient* cli = list_entry(c, opacliClient, client);
	if (cli->useTls) {
		err = opatlsStateWrite(&cli->tls, buff, len, &tot);
	} else {
		err = opasockSend(&cli->s, buff, len, &tot);
	}
	if (err && err != OPA_ERR_WOULDBLOCK) {
		cli->needsClosed = 1;
	}
	return tot;
}

static void opacliClientErrCB(opac* c, int errCode) {
	opacliClient* cli = list_entry(c, opacliClient, client);
	if (errCode == OPA_ERR_PARSE) {
		OPALOGERR("error parsing response from server");
	}
	int err = opasockClose(&cli->s);
	if (err) {
		OPALOGERRF("err %d trying to close conn", err);
	}
}

static int tlssockReadCB(void* cbdata, void* buff, size_t numToRead, size_t* pNumRead) {
	opacliClient* c = (opacliClient*) cbdata;
	return opasockRecv(&c->s, buff, numToRead, pNumRead);
}

static int tlssockWriteCB(void* cbdata, const void* buff, size_t numToWrite, size_t* pNumWritten) {
	opacliClient* c = (opacliClient*) cbdata;
	return opasockSend(&c->s, buff, numToWrite, pNumWritten);
}

#if !USELINENOISE
static char* linenoise(const char* prompt) {
	UNUSED(prompt);
	OPAPANIC("should not call");
}
static void linenoiseFree(void* ptr) {
	UNUSED(ptr);
	OPAPANIC("should not call");
}
static int linenoiseHistoryAdd(const char* line) {
	UNUSED(line);
	OPAPANIC("should not call");
}
#endif



#ifdef _WIN32
static int opacliGetPassFromTerm(FILE* fin, FILE* fout, int mask, opabuff* b) {
	// TODO: print mask character when user types a character
	UNUSED(fout);
	UNUSED(mask);
	DWORD origMode;
	intptr_t inth = _get_osfhandle(_fileno(fin));
	HANDLE h = (HANDLE) inth;
	if (!GetConsoleMode(h, &origMode)) {
		LOGWINERR();
		return OPA_ERR_INTERNAL;
	}
	if (!SetConsoleMode(h, origMode & (~ENABLE_ECHO_INPUT))) {
		LOGWINERR();
		return OPA_ERR_INTERNAL;
	}
	int err = opaGetLineWinConsole(h, b);
	if (!SetConsoleMode(h, origMode)) {
		LOGWINERR();
	}
	return err;
}
#else

static int opacliReadPass(FILE* fin, FILE* fout, int mask, opabuff* b) {
	int err = 0;
	size_t origLen = opabuffGetLen(b);

	mask = mask > 0x1f && mask < 0x7f ? mask : 0;

	while (!err) {
		int ch = fgetc(fin);
		if (ch == EOF) {
			err = OPA_ERR_INTERNAL;
			break;
		}
		if (ch == '\n') {
			break;
		}
		if (ch != 0x7f && ch != 0x08) {
			if (mask && (ch <= 0x7f || (ch & 0x40))) {
				// only print mask if byte read was 1st byte of utf-8 character
				fputc(mask, fout);
			}
			err = opabuffAppend1(b, ch);
		} else if (opabuffGetLen(b) > 0) {
			if (mask) {
				fputc(0x8, fout);
				fputc(' ', fout);
				fputc(0x8, fout);
			}
			while (opabuffGetLen(b) > 0) {
				uint8_t delb = *opabuffGetPos(b, opabuffGetLen(b) - 1);
				opabuffSetLen(b, opabuffGetLen(b) - 1);
				if (delb <= 0x7f || (delb & 0x40)) {
					// if deleted byte was 1st byte of utf-8 character, then done deleting bytes
					break;
				}
			}
		}
	}
	if (!err) {
		err = opabuffAppend1(b, 0);
	}

	if (err) {
		// on err, zero any chars that were added to buff and set len back to orig
		opabuffSetLen(b, origLen);
	}

	return err;
}

static int opacliGetPassFromTerm(FILE* fin, FILE* fout, int mask, opabuff* b) {
	struct termios origAttr;
	struct termios hideAttr;
	if (tcgetattr(fileno(fin), &origAttr)) {
		return OPA_ERR_INTERNAL;
	}
	hideAttr = origAttr;
	hideAttr.c_lflag &= ~(ICANON | ECHO);
	hideAttr.c_cc[VTIME] = 0;
	hideAttr.c_cc[VMIN] = 1;
	if (tcsetattr(fileno(fin), TCSANOW, &hideAttr)) {
		return OPA_ERR_INTERNAL;
	}
	int err = opacliReadPass(fin, fout, mask, b);
	if (tcsetattr(fileno(fin), TCSANOW, &origAttr)) {
		// TODO: log err if cannot set terminal back to orig mode?
	}
	return err;
}
#endif

static void opacliClientClose(opacliClient* c) {
	opasockClose(&c->s);
	opacClose(&c->client);
	c->needsClosed = 0;
	opatlsStateClear(&c->tls);
}

static void opacliQueueSendRecv(opacliClient* c, opacReq* req) {
	opacQueueRequest(&c->client, req);
	while (!opacReqIsSent(req) && opacIsOpen(&c->client)) {
		if (c->needsClosed) {
			opacliClientClose(c);
			break;
		}
		opacSendRequests(&c->client);
	}
	while (!opacReqResponseRecvd(req) && opacIsOpen(&c->client)) {
		if (c->needsClosed) {
			opacliClientClose(c);
			break;
		}
		opacParseResponses(&c->client);
	}
}

static char* opastrdup(const char* s) {
	if (s == NULL) {
		return NULL;
	}
	size_t len = strlen(s);
	char* c = OPAMALLOC(len + 1);
	if (c != NULL) {
		memcpy(c, s, len + 1);
	}
	return c;
}

static void freepass(char* p) {
	if (p != NULL) {
		memset(p, 0, strlen(p));
		OPAFREE(p);
	}
}

/**
 * Synchronously send/recv AUTH request with specified password
 * @return 0 if AUTH completed successfully; else error code
 */
static int opacliSyncAuth(opacliClient* c, const char* pass) {
	static const char* AUTHCMD = "AUTH";
	static const size_t AUTHLEN = 4;
	OASSERT(AUTHLEN == strlen(AUTHCMD));

	size_t passLen = strlen(pass);
	size_t passSerLen = passLen == 0 ? 1 : 1 + opaviStoreLen(passLen) + passLen;
	size_t lenReq = 1 + 1 + (1 + opaviStoreLen(AUTHLEN) + AUTHLEN) + (passSerLen) + 1;

	opabuff buff;
	opabuffInit(&buff, OPABUFF_F_NOPAGING | OPABUFF_F_ZERO);
	int err = opabuffSetLen(&buff, lenReq);
	if (err) {
		opabuffFree(&buff);
		return err;
	}

	uint8_t* pos = opabuffGetPos(&buff, 0);
	*pos++ = OPADEF_ARRAY_START;
	*pos++ = OPADEF_NULL;
	*pos++ = OPADEF_STR_LPVI;
	pos = opaviStore(AUTHLEN, pos);
	memcpy(pos, AUTHCMD, AUTHLEN);
	pos += AUTHLEN;
	if (passLen != 0) {
		*pos++ = OPADEF_STR_LPVI;
		pos = opaviStore(passLen, pos);
		memcpy(pos, pass, passLen);
		pos += passLen;
	} else {
		*pos++ = OPADEF_STR_EMPTY;
	}
	*pos++ = OPADEF_ARRAY_END;
	OASSERT(pos == opabuffGetPos(&buff, 0) + lenReq);

	opacReq req;
	opacReqInit(&req);
	opacReqSetRequestBuff(&req, buff);
	// note: once req is sent, opabuffFree() will be called for the request which should zero the memory
	opacliQueueSendRecv(c, &req);

	int authErr = opacIsOpen(&c->client) && opacReqResponseRecvd(&req) && !opacReqResponseIsErr(&req) ? 0 : OPA_ERR_INTERNAL;
	opacReqFreeResponse(&req);

	if (!authErr) {
		if (c->authpass == NULL) {
			c->authpass = opastrdup(pass);
		} else if (strcmp(pass, c->authpass) != 0) {
			freepass(c->authpass);
			c->authpass = opastrdup(pass);
		}
	}

	return authErr;
}

/**
 * synchronously send/recv a PING request to determine whether AUTH is needed
 * @return 1 if server replies with AUTH required error; else 0 if server replies with PONG or some error occurs
 */
static int opacliIsAuthNeeded(opacliClient* c) {
	int authreq = 0;
	oparb ureq = oparbParseUserCommand("PING");
	if (!ureq.err) {
		opacReq req;
		opacReqInit(&req);
		opacReqSetRequestBuff(&req, ureq.buff);
		opacliQueueSendRecv(c, &req);
		if (opacIsOpen(&c->client) && opacReqResponseRecvd(&req) && opacReqResponseIsErr(&req)) {
			opacRpcError errObj;
			int err = opacReqLoadErrObj(&req, &errObj);
			if (!err && errObj.code == ERR_AUTHREQ) {
				authreq = 1;
			}
		}
		opacReqFreeResponse(&req);
	}
	return authreq;
}

static void printAndFlush(FILE* f, const char* str) {
	opa_fprintf(f, "%s", str);
	fflush(f);
}

static void opacliDoAuth2(opacliClient* c, const char* pass, int promptOnFailure, FILE* fin, FILE* fout) {
	opabuff buff;
	opabuffInit(&buff, OPABUFF_F_NOPAGING | OPABUFF_F_ZERO);

	while (1) {
		if (pass == NULL) {
			// TODO: print host?
			opabuffSetLen(&buff, 0);
			printAndFlush(fout, "password: ");
			if (opacliGetPassFromTerm(fin, fout, '*', &buff)) {
				opabuffFree(&buff);
				opa_fprintf(stderr, "error reading password\n");
				exit(EXIT_FAILURE);
			}
			printAndFlush(fout, "\n");
			pass = (const char*) opabuffGetPos(&buff, 0);
		}
		if (pass == NULL) {
			break;
		}

		int authErr = opacliSyncAuth(c, pass);
		if (!authErr) {
			break;
		}

		// TODO: if authErr indicates that a problem occurred other than invalid password, then return error code

		printAndFlush(fout, "auth failed\n");
		if (!promptOnFailure) {
			opabuffFree(&buff);
			exit(EXIT_FAILURE);
		}
		pass = NULL;
	}

	opabuffFree(&buff);
}

static void opacliDoAuth(opacliClient* c, const char* pass, int prompt) {
	if (prompt && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
		// handle case where user has redirected stdin from a file and wants to type a password in terminal
#ifdef _WIN32
		FILE* fin  = fopen("CONIN$",  "r+");
		FILE* fout = fopen("CONOUT$", "a");
		if (fin == NULL || fout == NULL) {
			OPALOGERR("cannot open CONIN$ or CONOUT$ to prompt for password");
			exit(EXIT_FAILURE);
		}
		opacliDoAuth2(c, pass, prompt, fin, fout);
		fclose(fin);
		fclose(fout);
#else
		FILE* ftty = fopen("/dev/tty", "r+");
		if (ftty == NULL) {
			OPALOGERR("cannot open /dev/tty to prompt for password");
			exit(EXIT_FAILURE);
		}
		opacliDoAuth2(c, pass, prompt, ftty, ftty);
		fclose(ftty);
#endif
	} else {
		opacliDoAuth2(c, pass, prompt, stdin, stdout);
	}
}

static void printResult(const opacReq* req, const char* indent) {
	// TODO: when stringifying, should detect whether characters can be displayed and if not then escape to Unicode
	//   escape sequence. how to determine if char is printable? isprint/iswprint?
	char* resultStr = opasoStringify(opacReqGetResponse(req), indent);
	if (resultStr != NULL) {
		if (opacReqResponseIsErr(req)) {
			opa_fprintf(stderr, STR_ERROR "%s\n", resultStr);
		} else {
			opa_printf("%s\n", resultStr);
		}
	} else {
		opa_fprintf(stderr, "%s\n", "error stringifying response");
	}
	OPAFREE(resultStr);
}

static int opacliClientConnect(opacliClient* clic, const opacliConnectOptions* opts) {
	int err = 0;
	// note: the following arrays of callback funcs must be static!
	static const opacFuncs IOFUNCS = {opacliReadCB, opacliWriteCB, opacliClientErrCB, NULL, NULL, NULL, NULL};
	static const opatlsioStreamCBs STREAMCBS = {tlssockReadCB, tlssockWriteCB};

	if (!clic->connectedOnce) {
		clic->useTls = opts->useTLS;
	}

	opasockInit(&clic->s);
	opatlsStateInit(&clic->tls);
	opacInit(&clic->client, &IOFUNCS);

	if (!err) {
		// TODO: this function should return err code
		opasockConnect(&clic->s, opts->host, opts->port);
		if (clic->s.sid == SOCKID_NONE) {
			if (!clic->connectedOnce) {
				OPALOGERRF("unable to connect; addr=%s port=%u", opts->host, opts->port);
				exit(EXIT_FAILURE);
			} else {
				return 0;
			}
		}
	}

	// note: there's some funky logic happening below. The intended behavior is as follows:
	//  - If client is connecting for the first time and the host is determined to be a
	//    loopback address, then conn is allowed to skip TLS (if useTLS is appropriate level; ie,
	//    tls-always was not requested)
	//  - If client is reconnecting, then it must continue to use TLS if TLS was used previously.
	//    Therefore, the connection cannot drop from using TLS to not using TLS, even if address
	//    is determined to be loopback.

	if (!err && opts->useTLS == 2 && !clic->connectedOnce && opasockIsLoopback(&clic->s)) {
		// if connecting to loopback address then don't use TLS. This helps development by avoiding
		//  cert generation/verification issues when not connecting to different machine over
		//  network. Note that there may be potential security issues if this machine is being
		//  used by multiple (untrusted) people/apps at once.
		clic->useTls = 0;
		if (opts->printStatus) {
			printAndFlush(stderr, "Connection to localhost detected. TLS encryption disabled. Use --tls-always if encryption is desired.\n");
		}
	}

	// detect the case where the client first connected to a loopback host and was able to avoid using TLS
	//   but when reconnecting, the host is no longer a loopback address and TLS is now required.
	if (!err && opts->useTLS == 2 && !clic->useTls && clic->connectedOnce && !opasockIsLoopback(&clic->s)) {
		clic->useTls = 2;
	}

	if (clic->useTls && !err) {
		if (!err) {
			err = opatlsConfigSetupNewState(opts->tlscfg, &clic->tls, NULL);
		}
		if (!err) {
			opatlsStateSetCallbackData(&clic->tls, clic, &STREAMCBS);
		}
		if (!err) {
			err = opatlsStateSetExpectedHost(&clic->tls, opts->sni != NULL ? opts->sni : opts->host);
		}
		if (!err) {
			err = opatlsStateHandshake(&clic->tls);
			if (err) {
				OPALOGERR("TLS handshake failed");
			}
		}
	}

	if (!err) {
		if (clic->connectedOnce) {
			if (clic->authpass != NULL || (opts->istty && opacliIsAuthNeeded(clic))) {
				opacliDoAuth(clic, clic->authpass, opts->istty);
			}
		} else {
			if (opts->pass != NULL || opts->authp || (opts->istty && opacliIsAuthNeeded(clic))) {
				opacliDoAuth(clic, opts->pass, opts->istty);
			}
		}
	}

	if (!err) {
		clic->connectedOnce = 1;
	} else {
		opacliClientClose(clic);
	}

	return err ? 0 : 1;
}

static void reconnect(opacliClient* clic, const opacliConnectOptions* opts) {
	unsigned long tries = 0;
	while (1) {
		if (opacliClientConnect(clic, opts)) {
			if (opts->printStatus && tries > 0) {
				opa_fprintf(stderr, "Reconnected\n");
			}
			break;
		}
		if (opts->printStatus) {
			if (tries == 0) {
				opa_fprintf(stderr, "Disconnected from server. Attempting to reconnect (%s:%d)...\n", opts->host, opts->port);
			}
			opa_fprintf(stderr, "%lu\r", tries++);
			fflush(stderr);
		}
		usleep(1000000);
	}
}

static int reqIsCommand(const oparb* rb, const char* cmd) {
	const uint8_t* buff = opabuffGetPos(&rb->buff, 0);
	if (*buff == OPADEF_ARRAY_START) {
		++buff;
		if (*buff != OPADEF_ARRAY_END) {
			buff += opasolen(buff);
			size_t strLen;
			int err = opasoGetStrOrBin(buff, &buff, &strLen);
			if (!err) {
				return opaStrCmpNoCaseAsciiLen(buff, strLen, cmd, strlen(cmd)) == 0;
			}
		}
	}
	return 0;
}

#if defined(OPA_MBEDTLS) || defined(OPABIGINT_USE_MBED)
static void* opacliMbedCalloc(size_t nmemb, size_t sz) {
	return OPACALLOC(nmemb, sz);
}

static void opacliMbedFree(void* ptr) {
	OPAFREE(ptr);
}
#endif

static int mainInternal(int argc, const char* argv[]) {
	#ifdef _WIN32
		opacliWsaStartup();
	#endif
	#if defined(OPA_MBEDTLS) || defined(OPABIGINT_USE_MBED)
		mbedtls_platform_set_calloc_free(opacliMbedCalloc, opacliMbedFree);
	#endif

	FILE* src = stdin;
	char istty = isatty(STDIN_FILENO);

	opacliClient clic = {0};
	opacliConnectOptions connOpts = {
		.host = DEFAULT_HOST,
		.sni = NULL,
		.port = 4567,
		.useTLS = 2,
		.istty = istty,
		.printStatus = istty && isatty(STDERR_FILENO),
		.authp = 0,
		.tlscfg = NULL
	};

	// TODO: features to add:
	//  option for connect timeout
	//  option for command response timeout
	//  support for multi line (if string/array/etc is not finished then continue typing request on next line; or end line with "\" char)
	//  strict parsing mode (must quote strings)? json input/output mode?

	int err = 0;
	const char* binName = argc > 0 ? argv[0] : "";
	const char* indent = "    ";
	const char* prompt = "> ";
	int usercmdIdx = 0;
	char readArgFromStdin = 0;
	char useLinenoise = USELINENOISE && istty && isatty(STDOUT_FILENO);
	char autoReconnect = istty;
	long interval = 0;
	long long repeat = 1;
	const opatlsLib* tlsLib2 = NULL;
	char verifyPeer = 1;
	const char* cacert = NULL;
	const char* cert = NULL;
	const char* key = NULL;
	const char* certP12 = NULL;
	const char* certPass = NULL;
	int lastReqWasErr = 0;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
			connOpts.host = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			connOpts.port = (uint16_t) argtouir(argv[++i], 1, UINT16_MAX, "-p");
		} else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
			connOpts.pass = argv[++i];
		} else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
			repeat = strtoll(argv[++i], NULL, 0);
		} else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			interval = atof(argv[++i]) * 1000000;
		} else if (strcmp(argv[i], "-x") == 0) {
			readArgFromStdin = 1;
		} else if (strcmp(argv[i], "--authp") == 0) {
			connOpts.authp = 1;
		} else if (strcmp(argv[i], "--nolinenoise") == 0) {
			useLinenoise = 0;
		} else if (strcmp(argv[i], "--indent") == 0 && i + 1 < argc) {
			indent = argv[++i];
		} else if (strcmp(argv[i], "--sni") == 0 && i + 1 < argc) {
			connOpts.sni = argv[++i];
		} else if (strcmp(argv[i], "--cacert") == 0 && i + 1 < argc) {
			cacert = argv[++i];
		} else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
			cert = argv[++i];
		} else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
			key = argv[++i];
		} else if (strcmp(argv[i], "--cert-p12") == 0 && i + 1 < argc) {
			certP12 = argv[++i];
		} else if (strcmp(argv[i], "--cert-pass") == 0 && i + 1 < argc) {
			certPass = argv[++i];
		} else if (strcmp(argv[i], "--no-verify-peer") == 0) {
			verifyPeer = 0;
		} else if (strcmp(argv[i], "--no-tls") == 0) {
			connOpts.useTLS = 0;
		} else if (strcmp(argv[i], "--tls-always") == 0) {
			connOpts.useTLS = 3;
		} else if (strcmp(argv[i], "--tls-lib") == 0 && i + 1 < argc) {
			tlsLib2 = tlsutilsGetLib(argv[i + 1]);
			if (tlsLib2 == NULL) {
				opa_fprintf(stderr, "unsupported tls library \"%s\"\n", argv[i + 1]);
				exit(EXIT_FAILURE);
			}
			++i;
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-help") == 0) {
			printUsage(binName, EXIT_SUCCESS);
		} else if (strcmp(argv[i], "--version") == 0) {
			const opacBuildInfo* ocbi = opacGetBuildInfo();
			opa_printf("opacli %s (opac %s; %s; %s)\n", PPXSTR(OPACLI_VERSION), ocbi->version, ocbi->threadSupport ? "threads" : "no-threads", ocbi->bigIntLib);
#ifdef OPA_OPENSSL
			const char* vstr = opensslGetVersionStr();
			if (vstr != NULL) {
				opa_printf("%s\n", vstr);
			}
#endif
#ifdef OPA_MBEDTLS
			{
				char tmp[32];
				mbedtls_version_get_string_full(tmp);
#ifdef MBEDTLS_GIT_HASH
				opa_printf("%s (%s)\n", tmp, PPXSTR(MBEDTLS_GIT_HASH));
#else
				opa_printf("%s\n", tmp);
#endif
			}
#endif
			exit(EXIT_SUCCESS);
		} else if (strcmp(argv[i], "--licenses") == 0) {
			const char* sep = "-------------------------------------------------------------------------\n";
			opa_printf("Depending on how it is configured, this project may include source code from any of the following:\n\n");
			const char* licenses[] = {
#if defined(OPA_MBEDTLS) || defined(OPABIGINT_USE_MBED)
				mbedtlsLicense1, mbedtlsLicense2, mbedtlsLicense3, sep,
#endif
				linenoiseLicense, sep, libtomLicense, sep, libdlbLicense, sep, opatomicLicense};
			for (size_t j = 0; j < sizeof(licenses) / sizeof(licenses[0]); ++j) {
				opa_printf("%s\n", licenses[j]);
			}
			exit(EXIT_SUCCESS);
		} else {
			if (argv[i][0] != '-') {
				usercmdIdx = i;
				break;
			}
			opa_fprintf(stderr, "unknown option or arg missing\n");
			printUsage(binName, EXIT_FAILURE);
		}
	}

	if (connOpts.useTLS && tlsLib2 == NULL) {
		tlsLib2 = tlsutilsGetDefaultLib();
		if (tlsLib2 == NULL) {
			opa_fprintf(stderr, "cannot load default tls library\n");
			exit(EXIT_FAILURE);
		}
	}

	if (usercmdIdx > 0) {
		autoReconnect = 0;
		connOpts.printStatus = 0;
	}

	if (connOpts.useTLS && !err) {
		err = opatlsConfigNew(tlsLib2, 0, &connOpts.tlscfg);
		if (!err) {
			err = opatlsConfigVerifyPeer(connOpts.tlscfg, verifyPeer);
		}
#ifdef OPA_MBEDTLS
		if (!err && tlsLib2 == &mbedLib && cacert == NULL) {
			cacert = mbedGetDefaultCAPath();
		}
#endif
		if (!err && cacert != NULL) {
			err = opatlsConfigAddCACertsFile(connOpts.tlscfg, cacert);
		}
		if (!err && (cert != NULL && key != NULL)) {
			err = opatlsConfigUseCert(connOpts.tlscfg, cert, key);
		}
		if (!err && certP12 != NULL) {
			err = opatlsConfigUseCertP12(connOpts.tlscfg, certP12, certPass);
		}
	}

	if (err) {
		OPALOGERRF("err %d occurred", err);
		exit(EXIT_FAILURE);
	}

	if (!opacliClientConnect(&clic, &connOpts)) {
		OPALOGERR("error occurred when connecting");
		exit(EXIT_FAILURE);
	}

	if (useLinenoise && usercmdIdx > 0) {
		useLinenoise = 0;
	}
	opabuff lineb;
	opabuffInit(&lineb, 0);
	char* line = NULL;

	if (usercmdIdx > 0) {
		for (int i = usercmdIdx; !err && i < argc; ++i) {
			err = opabuffAppend(&lineb, argv[i], strlen(argv[i]));
			if (!err) {
				err = opabuffAppend1(&lineb, ' ');
			}
		}
		if (!err && readArgFromStdin && !istty) {
			err = opabuffAppend(&lineb, " ", 1);
			uint8_t buff[512];
			while (!err && !feof(src)) {
				if (ferror(src)) {
					LOGSYSERRNO();
					exit(EXIT_FAILURE);
				}
				size_t numRead = fread(buff, 1, sizeof(buff), src);
				if (numRead > 0) {
					err = opabuffAppend(&lineb, buff, numRead);
				}
			}
		}
		if (!err) {
			err = opabuffAppend1(&lineb, '\0');
		}
		if (!err) {
			line = (char*) opabuffGetPos(&lineb, 0);
		}
	}

	while (1) {
		if (usercmdIdx > 0) {
			// non-interactive; line already parsed
		} else if (useLinenoise) {
			linenoiseFree(line);
			line = linenoise(prompt);
			if (line == NULL) {
				break;
			}
		} else {
			if (istty) {
				opa_printf("%s", prompt);
			}
			if (!err) {
				err = opaGetLine(src, &lineb);
			}
			if (!err) {
				if (opabuffGetLen(&lineb) == 0) {
					break;
				}
				line = (char*) opabuffGetPos(&lineb, 0);
			}
		}

		if (err || line == NULL) {
			opa_fprintf(stderr, "err %d occurred when reading line\n", err);
			exit(EXIT_FAILURE);
		}

		if (line[strspn(line, " \t\r\n")] == 0) {
			// skip empty line (contains only whitespace)
			continue;
		}

		oparb ureq = oparbParseUserCommand(line);
		if (ureq.err) {
			if (ureq.errDesc == NULL) {
				opa_fprintf(stderr, "parse error: %d\n", ureq.err);
			} else {
				opa_fprintf(stderr, "parse error: %s\n", ureq.errDesc);
			}
			if (useLinenoise) {
				linenoiseHistoryAdd(line);
			}
			if (usercmdIdx > 0) {
				break;
			}
			continue;
		}

		if (reqIsCommand(&ureq, "quit") || reqIsCommand(&ureq, "exit")) {
			opabuffFree(&ureq.buff);
			break;
		}
		int isShutdown = reqIsCommand(&ureq, "shutdown");

		if (autoReconnect && (!opacIsOpen(&clic.client) || !opasockMayRecvMore(&clic.s, 0))) {
			reconnect(&clic, &connOpts);
		}

		opacReq req;
		opacReqInit(&req);
		opacReqSetRequestBuff(&req, ureq.buff);
		opacliQueueSendRecv(&clic, &req);
		if (opacReqResponseRecvd(&req)) {
			lastReqWasErr = opacReqResponseIsErr(&req);
			printResult(&req, indent);
		} else {
			lastReqWasErr = 1;
			if (!opacIsOpen(&clic.client)) {
				if (!isShutdown) {
					printAndFlush(stderr, STR_ERROR "disconnected\n");
				}
			} else {
				printAndFlush(stderr, STR_ERROR "response not received\n");
			}
		}
		opacReqFreeResponse(&req);

		if (!opacIsOpen(&clic.client)) {
			if (autoReconnect) {
				reconnect(&clic, &connOpts);
			} else {
				break;
			}
		}

		if (usercmdIdx > 0) {
			if (repeat > 0 && --repeat == 0) {
				break;
			}
			if (interval > 0) {
				usleep(interval);
			}
		}
		if (useLinenoise) {
			linenoiseHistoryAdd(line);
		}
	}

	if (useLinenoise) {
		linenoiseFree(line);
	}

	opabuffFree(&lineb);

	if (opatlsStateHandshakeCompleted(&clic.tls)) {
		opatlsStateNotifyPeerClosing(&clic.tls);
	}
	opacliClientClose(&clic);
	freepass(clic.authpass);
	opatlsConfigRemRef(connOpts.tlscfg);

#if defined(OPADBG) && defined(OPAMALLOC)
#ifdef OPA_OPENSSL
	opensslCloseLib();
#endif
	const opamallocStats* mstats = opamallocGetStats();
	if (mstats->allocs > 0) {
		opa_fprintf(stderr, "memory leak? allocs: %lu\n", mstats->allocs);
	}
#endif

	return lastReqWasErr ? EXIT_FAILURE : EXIT_SUCCESS;
}

#ifdef _WIN32
int wmain(int argc, wchar_t* argv[]);
int wmain(int argc, wchar_t* argv[]) {
	char** argv2 = OPAMALLOC(argc * sizeof(char*));
	if (argv2 == NULL) {
		OPALOGERR("unable to allocate memory");
		exit(EXIT_FAILURE);
	}
	for (int i = 0; i < argc; ++i) {
		int err = winWideToUtf8(argv[i], &argv2[i]);
		if (err) {
			OPALOGERR("error converting argv wide string to utf-8");
			exit(EXIT_FAILURE);
		}
	}
	// note: leaking memory (argv utf-8 strings and argv2 array) because program is exiting
	return mainInternal(argc, (const char**) argv2);
}
#else
int main(int argc, const char* argv[]) {
	return mainInternal(argc, argv);
}
#endif
