/*
 * Copyright 2018-2019 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifndef _WIN32
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
#define strcasecmp _stricmp
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
#include <strings.h>
#include <termios.h>
#include <unistd.h>
#ifndef USELINENOISE
#define USELINENOISE 1
#endif
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


#ifndef OPACLI_VERSION
#define OPACLI_VERSION "0.0.0-dev"
#endif

#define STR_ERROR "ERROR: "
#define DEFAULT_HOST "localhost"

// TODO: this error code will be changing
#define ERR_AUTHREQ -53


typedef struct {
	opasock s;
	opac client;
} opacliClient;




static unsigned int argtouir(const char* s, unsigned int min, unsigned int max, const char* argname) {
	unsigned long v = strtoul(s, NULL, 0);
	if (v < min || v > max || (v == ULONG_MAX && errno == ERANGE)) {
		OPALOGERRF("arg \"%s\" out of range", argname);
		exit(EXIT_FAILURE);
	}
	return v;
}

static void printUsage(const char* bin, int exitCode) {
	printf("Usage: %s [OPTIONS] [cmd [arg [arg ...]]]\n"
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

static void usleep(unsigned long usec) {
	LARGE_INTEGER li;
	// SetWaitableTimer: negative value indicates relative time; positive value indicate absolute time
	//  value is in 100-nanosecond intervals
	li.QuadPart = 0LL - ((long long)usec * 10);
	HANDLE ht = CreateWaitableTimer(NULL, TRUE, NULL);
	if (ht != NULL) {
		if (SetWaitableTimer(ht, &li, 0, NULL, NULL, FALSE)) {
			WaitForSingleObject(ht, INFINITE);
		} else {
			LOGWINERR();
		}
		if (!CloseHandle(ht)) {
			LOGWINERR();
		}
	} else {
		LOGWINERR();
	}
}

static int opaGetLineWinConsole(HANDLE h, opabuff* b) {
	int err = 0;
	opabuff wbuff = {0};
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
	opacliClient* cli = list_entry(c, opacliClient, client);
	int err = opasockRecv(&cli->s, buff, len, &tot);
	if (err) {
		// TODO: close client and detect closed client from loop; allow reconnect?
		if (err == OPA_ERR_EOF) {
			// peer has performed orderly shutdown
			// TODO: if a response is outstanding then exit with error code?
			printf("socket closed\n");
			exit(EXIT_SUCCESS);
		}
		printf("socket err in recv; err %d\n", err);
		exit(EXIT_FAILURE);
	}
	return tot;
}

static size_t opacliWriteCB(opac* c, const void* buff, size_t len) {
	size_t tot;
	opacliClient* cli = list_entry(c, opacliClient, client);
	int err = opasockSend(&cli->s, buff, len, &tot);
	if (err) {
		// TODO: close client and detect closed client from loop; allow reconnect?
		printf("socket err in send; err %d\n", err);
		exit(EXIT_FAILURE);
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

static void opacQueueSendRecv(opac* c, opacReq* req) {
	opacQueueRequest(c, req);
	while (!opacReqIsSent(req) && opacIsOpen(c)) {
		opacSendRequests(c);
	}
	while (!opacReqResponseRecvd(req) && opacIsOpen(c)) {
		opacParseResponses(c);
	}
}

/**
 * Synchronously send/recv AUTH request with specified password
 * @return 0 if AUTH completed successfully; else error code
 */
static int opacSecureAuth(opac* c, const char* pass) {
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
	opacQueueSendRecv(c, &req);

	int authErr = opacIsOpen(c) && opacReqResponseRecvd(&req) && !opacReqResponseIsErr(&req) ? 0 : OPA_ERR_INTERNAL;
	opacReqFreeResponse(&req);
	return authErr;
}

/**
 * synchronously send/recv a PING request to determine whether AUTH is needed
 * @return 1 if server replies with AUTH required error; else 0 if server replies with PONG or some error occurs
 */
static int opacIsAuthNeeded(opac* c) {
	int authreq = 0;
	oparb ureq = oparbParseUserCommand("PING");
	if (!ureq.err) {
		opacReq req;
		opacReqInit(&req);
		opacReqSetRequestBuff(&req, ureq.buff);
		opacQueueSendRecv(c, &req);
		if (opacIsOpen(c) && opacReqResponseRecvd(&req) && opacReqResponseIsErr(&req)) {
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
	fputs(str, f);
	fflush(f);
}

static void opacliDoAuth2(opac* c, const char* pass, int prompt, FILE* fin, FILE* fout) {
	if (pass == NULL && !prompt) {
		return;
	}
	opabuff buff;
	opabuffInit(&buff, OPABUFF_F_NOPAGING | OPABUFF_F_ZERO);

	while (1) {
		if (prompt) {
			// TODO: print host?
			opabuffSetLen(&buff, 0);
			printAndFlush(fout, "password: ");
			if (opacliGetPassFromTerm(fin, fout, '*', &buff)) {
				opabuffFree(&buff);
				fprintf(stderr, "error reading password\n");
				exit(EXIT_FAILURE);
			}
			printAndFlush(fout, "\n");
			pass = (const char*) opabuffGetPos(&buff, 0);
		}
		if (pass == NULL) {
			break;
		}

		int authErr = opacSecureAuth(c, pass);
		if (!authErr) {
			break;
		}

		printAndFlush(fout, "auth failed\n");
		if (!prompt) {
			opabuffFree(&buff);
			exit(EXIT_FAILURE);
		}
	}

	opabuffFree(&buff);
}

static void opacliDoAuth(opac* c, const char* pass, int prompt) {
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

#ifdef _WIN32
static void winPrintUtf8(FILE* f, const char* str) {
	int fd = _fileno(f);
	if (!isatty(fd)) {
		fputs(str, f);
		return;
	}
	wchar_t* wideStr = NULL;
	int err = winUtf8ToWide(str, &wideStr);
	if (!err) {
		HANDLE h;
		if (fd == STDOUT_FILENO) {
			h = GetStdHandle(STD_OUTPUT_HANDLE);
		} else if (fd == STDERR_FILENO) {
			h = GetStdHandle(STD_ERROR_HANDLE);
		} else {
			h = INVALID_HANDLE_VALUE;
		}
		if (h != INVALID_HANDLE_VALUE) {
			fflush(f);
			// note: _setmode + fputws doesn't seem to work on win2k; some unicode chars do not print
			WriteConsoleW(h, wideStr, wcslen(wideStr), NULL, NULL);
		} else {
			OPALOGERR("unknown file");
		}
	}
	OPAFREE(wideStr);
}
#endif

static void printResult(const opacReq* req, const char* indent) {
	// TODO: when stringifying, should detect whether characters can be displayed and if not then escape to Unicode
	//   escape sequence. how to determine if char is printable? isprint/iswprint?
	char* resultStr = opasoStringify(opacReqGetResponse(req), indent);
	if (resultStr != NULL) {
		if (opacReqResponseIsErr(req)) {
			fputs(STR_ERROR, stderr);
			#ifdef _WIN32
				winPrintUtf8(stderr, resultStr);
			#else
				fputs(resultStr, stderr);
			#endif
		} else {
			#ifdef _WIN32
				winPrintUtf8(stdout, resultStr);
			#else
				fputs(resultStr, stdout);
			#endif
		}
		fputs("\n", stdout);
	} else {
		fprintf(stderr, "error stringifying response\n");
	}
	OPAFREE(resultStr);
}

static int mainInternal(int argc, const char* argv[]) {
	#ifdef _WIN32
		opacliWsaStartup();
	#endif

	FILE* src = stdin;

	opacliClient clic = {0};
	const opacFuncs iofuncs = {opacliReadCB, opacliWriteCB, opacliClientErrCB, NULL, NULL, NULL, NULL};

	opasockInit(&clic.s);
	opacInit(&clic.client, &iofuncs);

	// TODO: features to add:
	//  option for connect timeout
	//  option for command response timeout
	//  support for multi line (if string/array/etc is not finished then continue typing request on next line; or end line with "\" char)
	//  auto reconnect if conn is closed?
	//  detect socket close when it happens rather than when sending next request
	//  strict parsing mode (must quote strings)? json input/output mode?

	int err = 0;
	const char* binName = argc > 0 ? argv[0] : "";
	const char* host = DEFAULT_HOST;
	const char* authPass = NULL;
	const char* indent = "    ";
	const char* prompt = "> ";
	int usercmdIdx = 0;
	uint16_t port = 4567;
	char readArgFromStdin = 0;
	char authPrompt = 0;
	char istty = isatty(STDIN_FILENO);
	char useLinenoise = USELINENOISE && istty && isatty(STDOUT_FILENO);
	long interval = 0;
	long long repeat = 1;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
			host = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			port = (uint16_t) argtouir(argv[++i], 1, UINT16_MAX, "-p");
		} else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
			authPass = argv[++i];
		} else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
			repeat = strtoll(argv[++i], NULL, 0);
		} else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			interval = atof(argv[++i]) * 1000000;
		} else if (strcmp(argv[i], "-x") == 0) {
			readArgFromStdin = 1;
		} else if (strcmp(argv[i], "--authp") == 0) {
			authPrompt = 1;
		} else if (strcmp(argv[i], "--nolinenoise") == 0) {
			useLinenoise = 0;
		} else if (strcmp(argv[i], "--indent") == 0 && i + 1 < argc) {
			indent = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-help") == 0) {
			printUsage(binName, EXIT_SUCCESS);
		} else if (strcmp(argv[i], "--version") == 0) {
			const opacBuildInfo* ocbi = opacGetBuildInfo();
			printf("opacli %s (opac %s; %s; %s)\n", OPACLI_VERSION, ocbi->version, ocbi->threadSupport ? "threads" : "no-threads", ocbi->bigIntLib);
			exit(EXIT_SUCCESS);
		} else if (strcmp(argv[i], "--licenses") == 0) {
			const char* licenses[] = {opatomicLicense, libtomLicense, linenoiseLicense, libdlbLicense};
			printf("Depending on how it is configured, this project may include source code from any of the following:\n\n");
			for (size_t j = 0; j < sizeof(licenses) / sizeof(licenses[0]); ++j) {
				if (j != 0) {
					printf("-------------------------------------------------------------------------\n");
				}
				printf("%s\n", licenses[j]);
			}
			exit(EXIT_SUCCESS);
		} else {
			if (argv[i][0] != '-') {
				usercmdIdx = i;
				break;
			}
			fprintf(stderr, "unknown option or arg missing\n");
			printUsage(binName, EXIT_FAILURE);
		}
	}

	if (!err) {
		// TODO: this function should return err code
		opasockConnect(&clic.s, host, port);
		if (clic.s.sid == SOCKID_NONE) {
			OPALOGERRF("unable to connect; addr=%s port=%u", host, port);
			exit(EXIT_FAILURE);
		}
	}

	// detect whether AUTH is required
	if (!authPrompt && istty && authPass == NULL && usercmdIdx == 0 && opacIsAuthNeeded(&clic.client)) {
		authPrompt = 1;
	}

	opacliDoAuth(&clic.client, authPass, authPrompt);

	if (useLinenoise && usercmdIdx > 0) {
		useLinenoise = 0;
	}
	opabuff lineb = {0};
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
				printf("%s", prompt);
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
			fprintf(stderr, "err %d occurred when reading line\n", err);
			exit(EXIT_FAILURE);
		}

		if (strcasecmp(line, "quit") == 0 || strcasecmp(line, "exit") == 0) {
			break;
		}

		if (line[strspn(line, " \t\r\n")] == 0) {
			// skip empty line (contains only whitespace)
			continue;
		}

		oparb ureq = oparbParseUserCommand(line);
		if (ureq.err) {
			if (ureq.errDesc == NULL) {
				fprintf(stderr, "parse error: %d\n", ureq.err);
			} else {
				fprintf(stderr, "parse error: %s\n", ureq.errDesc);
			}
			if (useLinenoise) {
				linenoiseHistoryAdd(line);
			}
			if (usercmdIdx > 0) {
				break;
			}
			continue;
		}

		opacReq req;
		opacReqInit(&req);
		opacReqSetRequestBuff(&req, ureq.buff);
		opacQueueSendRecv(&clic.client, &req);
		printResult(&req, indent);
		opacReqFreeResponse(&req);

		if (!opacIsOpen(&clic.client)) {
			break;
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

	opasockClose(&clic.s);
	opacClose(&clic.client);

#if defined(OPADBG) && defined(OPAMALLOC)
	const opamallocStats* mstats = opamallocGetStats();
	if (mstats->allocs > 0) {
		printf("memory leak? allocs: %lu\n", mstats->allocs);
	}
#endif

	return 0;
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
