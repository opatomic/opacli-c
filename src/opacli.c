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
// note: include winsock2.h here to make sure it is included before windows.h
#include <winsock2.h>
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


sockid CURRCONN = SOCKID_NONE;



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

static int opaGetLineWinConsole(opabuff* b) {
	int err = 0;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	wchar_t* wstr = NULL;
	size_t wlen = 0;
	while (!err) {
		wchar_t tmp[1];
		DWORD numRead;
		// note: ReadConsoleW is used because fgetwc has odd behavior when compiled on mingw-64 vs msvc. When
		//  compiled with mingw-64, fgetwc may return an extra newline character (does on win10; doesn't on win2k).
		//  Also, fgetwc does not seem to work right when trying to read unicode chars on win2k.
		//  In general, fgetwc seems buggy and inconsistent.
		if (!ReadConsoleW(h, tmp, sizeof(tmp) / sizeof(tmp[0]), &numRead, NULL)) {
			LOGWINERR();
			err = OPA_ERR_INTERNAL;
		}
		if (!err) {
			wchar_t* newStr = OPAREALLOC(wstr, sizeof(wchar_t) * (wlen + numRead));
			if (newStr == NULL) {
				err = OPA_ERR_NOMEM;
			} else {
				wstr = newStr;
				memcpy(wstr + wlen, tmp, numRead * sizeof(wchar_t));
				wlen += numRead;
			}
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
	OPAFREE(wstr);
	return err;
}

static int opaGetLine(FILE* f, opabuff* b) {
	if (isatty(_fileno(f))) {
		return opaGetLineWinConsole(b);
	} else {
		return opaGetLine2(f, b);
	}
}

#else

static int opaGetLine(FILE* f, opabuff* b) {
	return opaGetLine2(f, b);
}

#endif

static void opacliConnect(const char* addr, uint16_t port) {
	if (CURRCONN != SOCKID_NONE) {
		int err = opasockClose(CURRCONN);
		if (err) {
			OPALOGERRF("err %d trying to close conn", err);
		}
	}
	CURRCONN = opasockConnect(addr, port);
	if (CURRCONN == SOCKID_NONE) {
		// TODO: good log message
		exit(EXIT_FAILURE);
	}
}

static size_t opacliReadCB(opac* c, void* buff, size_t len) {
	UNUSED(c);
	size_t tot;
	int err = opasockRecv(CURRCONN, buff, len, &tot);
	if (err) {
		// TODO: close client and detect closed client from loop; allow reconnect?
		exit(EXIT_FAILURE);
	} else if (tot == 0) {
		// peer has performed orderly shutdown
		printf("socket closed\n");
		// TODO: if a response is outstanding then exit with error code?
		exit(0);
	}
	return tot;
}

static size_t opacliWriteCB(opac* c, const void* buff, size_t len) {
	UNUSED(c);
	size_t tot;
	int err = opasockSend(CURRCONN, buff, len, &tot);
	if (err) {
		// TODO: close client and detect closed client from loop; allow reconnect?
		exit(EXIT_FAILURE);
	}
	return tot;
}

static void opacliClientErrCB(opac* c, int errCode) {
	UNUSED(c);
	UNUSED(errCode);
	if (errCode == OPA_ERR_PARSE) {
		OPALOGERR("error parsing response from server");
	}
	int err = opasockClose(CURRCONN);
	if (err) {
		OPALOGERRF("err %d trying to close conn", err);
	}
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
#endif

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



static int opacliReadPass(int mask, opabuff* b) {
	int err = 0;
	size_t origLen = opabuffGetLen(b);

	mask = mask > 0x1f && mask < 0x7f ? mask : 0;

	while (!err) {
		int ch = fgetc(stdin);
		if (ch == EOF) {
			err = OPA_ERR_INTERNAL;
			break;
		}
		if (ch == '\n') {
			break;
		}
		if (ch != 0x7f && ch != 0x08) {
			if (mask) {
				fputc(mask, stdout);
			}
			err = opabuffAppend1(b, ch);
		} else if (opabuffGetLen(b) > 0) {
			if (mask) {
				fputc(0x8, stdout);
				fputc(' ', stdout);
				fputc(0x8, stdout);
			}
			opabuffSetLen(b, opabuffGetLen(b) - 1);
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

#ifdef _WIN32
static int opacliGetPassFromTerm(int mask, opabuff* b) {
	// TODO: print mask character when user types a character
	UNUSED(mask);
	DWORD origMode;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	if (!GetConsoleMode(h, &origMode)) {
		return OPA_ERR_INTERNAL;
	}
	if (!SetConsoleMode(h, origMode & (~ENABLE_ECHO_INPUT))) {
		return OPA_ERR_INTERNAL;
	}
	int err = opacliReadPass(0, b);
	if (!SetConsoleMode(h, origMode)) {
		// TODO: log err if cannot set console back to orig mode?
	}
	return err;
}
#else
static int opacliGetPassFromTerm(int mask, opabuff* b) {
	struct termios origAttr;
	struct termios hideAttr;
	if (tcgetattr(STDIN_FILENO, &origAttr)) {
		return OPA_ERR_INTERNAL;
	}
	hideAttr = origAttr;
	hideAttr.c_lflag &= ~(ICANON | ECHO);
	hideAttr.c_cc[VTIME] = 0;
	hideAttr.c_cc[VMIN] = 1;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &hideAttr)) {
		return OPA_ERR_INTERNAL;
	}
	int err = opacliReadPass(mask, b);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &origAttr)) {
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

static void opacliDoAuth(opac* c, const char* pass, int prompt) {
	if (pass == NULL && !prompt) {
		return;
	}
	opabuff buff;
	opabuffInit(&buff, OPABUFF_F_NOPAGING | OPABUFF_F_ZERO);

	while (1) {
		if (prompt) {
			// TODO: print host?
			opabuffSetLen(&buff, 0);
			printf("password: ");
			if (opacliGetPassFromTerm('*', &buff)) {
				opabuffFree(&buff);
				fprintf(stderr, "error reading password\n");
				exit(EXIT_FAILURE);
			}
			printf("\n");
			pass = (const char*) opabuffGetPos(&buff, 0);
		}
		if (pass == NULL) {
			break;
		}

		int authErr = opacSecureAuth(c, pass);
		if (!authErr) {
			break;
		}

		fprintf(stderr, "auth failed\n");
		if (!prompt) {
			opabuffFree(&buff);
			exit(EXIT_FAILURE);
		}
	}

	opabuffFree(&buff);
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

	const opacFuncs iofuncs = {opacliReadCB, opacliWriteCB, opacliClientErrCB, NULL, NULL, NULL, NULL};


	// TODO: features to add:
	//  option for connect timeout
	//  option for command response timeout
	//  support for multi line (if string/array/etc is not finished then continue typing request on next line; or end line with "\" char)
	//  auto reconnect if conn is closed?
	//  detect socket close when it happens rather than when sending next request
	//  strict parsing mode (must quote strings)? json input/output mode?
	//  allow strings to be single quoted?

	const char* binName = argc > 0 ? argv[0] : "";
	const char* host = DEFAULT_HOST;
	const char* authPass = NULL;
	const char* indent = "    ";
	const char* prompt = "> ";
	int usercmdIdx = 0;
	uint16_t port = 4567;
	char readArgFromStdin = 0;
	char authPrompt = 0;
	int istty = isatty(STDIN_FILENO);
	char useLinenoise = USELINENOISE && istty;
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

	opac c;
	opacInit(&c, &iofuncs);
	opacliConnect(host, port);

	// detect whether AUTH is required
	if (!authPrompt && istty && usercmdIdx == 0 && opacIsAuthNeeded(&c)) {
		authPrompt = 1;
	}

	opacliDoAuth(&c, authPass, authPrompt);

	if (useLinenoise && usercmdIdx > 0) {
		useLinenoise = 0;
	}
	opabuff lineb = {0};
	char* line = NULL;
	int err = 0;

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
			continue;
		}

		opacReq req;
		opacReqInit(&req);
		opacReqSetRequestBuff(&req, ureq.buff);
		opacQueueSendRecv(&c, &req);
		printResult(&req, indent);
		opacReqFreeResponse(&req);

		if (!opacIsOpen(&c)) {
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

	if (CURRCONN != SOCKID_NONE) {
		opasockClose(CURRCONN);
	}
	opacClose(&c);

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
