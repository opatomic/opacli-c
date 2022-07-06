/*
 * Copyright 2022 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 *
 * Utility to compile .c files in parallel. Designed for simplicity.
 * Read 3 lines from stdin as follows:
 *   1) working directory of the command
 *   2) command to run
 *   3) message to print when command succeeds (prints nothing if line is empty)
 * notes:
 *  - Runs a command concurrently for each core in the system.
 *  - Output from the commands may be interleaved rather than grouped.
 *  - If a command fails then any op that already started will continue to run but no more commands
 *    will be run; when all running commands stop then this program will exit with a non-zero exit
 *    code.
 *  - on linux, each command is piped as stdin to "sh" to handle the args parsing
 * Compiler incantations:
 *   gcc parallel.c -o parallel -std=c99 -Wall -Wextra -Wpedantic -Wshadow -O2 -s -lpthread
 *   i686-w64-mingw32-gcc parallel.c -o parallel.exe -std=c99 -Wall -Wextra -Wpedantic -Wshadow -D__USE_MINGW_ANSI_STDIO=0 -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0500 -DWINVER=0x0500 -O2 -s
 *   zig cc -target x86_64-macos parallel.c -o parallel -std=c99 -Wall -Wextra -Wpedantic -Wshadow -O2 -s -lpthread
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
typedef HANDLE pthread_t;
typedef CRITICAL_SECTION pthread_mutex_t;
#else
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <sys/sysinfo.h>
#elif defined(__FreeBSD__) || defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#define UNUSED(x) (void)(x)


pthread_mutex_t G_MUT;
volatile int G_EXITRES = EXIT_SUCCESS;

typedef struct {
	char* buff;
	size_t len;
	size_t allocLen;
} line;


#ifdef _WIN32

static int pthread_mutex_init(pthread_mutex_t* m, void* attr) {
	UNUSED(attr);
	InitializeCriticalSection(m);
	return 0;
}

static int pthread_mutex_lock(pthread_mutex_t* m) {
	EnterCriticalSection(m);
	return 0;
}

static int pthread_mutex_unlock(pthread_mutex_t* m) {
	LeaveCriticalSection(m);
	return 0;
}

#endif


static void logAndExit(const char* msg) {
	fprintf(stderr, "%s\n", msg);
	G_EXITRES = EXIT_FAILURE;
#ifdef _WIN32
	_endthreadex(0);
#else
	pthread_exit(NULL);
#endif
}

static int lineEnsureLen(line* l, size_t lenReq) {
	if (l->allocLen < lenReq) {
		size_t newAllocLen = l->allocLen == 0 ? 256 : l->allocLen * 2;
		newAllocLen = newAllocLen < lenReq ? lenReq : newAllocLen;
		char* newBuff = l->buff == NULL ? malloc(newAllocLen) : realloc(l->buff, newAllocLen);
		if (newBuff == NULL) {
			//fputs("error allocating memory\n", stderr);
			return 0;
		}
		l->buff = newBuff;
		l->allocLen = newAllocLen;
	}
	return 1;
}

static int readLine(line* l) {
	char tmpbuff[1];
	while (1) {
		// TODO: read/process more than a single byte at a time
		size_t num = fread(tmpbuff, 1, 1, stdin);
		if (ferror(stdin)) {
			fputs("ferror in fread() from stdin\n", stderr);
			return 0;
		} else if (feof(stdin)) {
			return 1;
		} else if (num > 0) {
			if (!lineEnsureLen(l, l->len + 1)) {
				fputs("error allocating memory\n", stderr);
				return 0;
			}
			l->buff[l->len++] = tmpbuff[0];
			if (tmpbuff[0] == '\n') {
				return 1;
			}
		}
	}
}

#ifdef _WIN32
static void winLogErr(DWORD errCode) {
	char* msgBuff = NULL;
	DWORD res = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*) &msgBuff, 0, NULL);
	if (res > 0 && msgBuff != NULL) {
		fprintf(stderr, "%s\n", msgBuff);
		LocalFree(msgBuff);
	}
}

static wchar_t* winUtf8ToWide(const char* utf8Str) {
	if (utf8Str == NULL) {
		return NULL;
	}
	int reqLen = MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, NULL, 0);
	if (reqLen == 0) {
		return NULL;
	}
	wchar_t* wideStr = malloc(reqLen * sizeof(wchar_t));
	if (wideStr == NULL) {
		return NULL;
	}
	int checkRes = MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, wideStr, reqLen);
	if (checkRes == 0) {
		free(wideStr);
		return NULL;
	}
	//assert(checkRes == reqLen);
	return wideStr;
}

static void runCommand(const char* dir, char* cmd, const char* msg) {
	STARTUPINFOW si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);

	wchar_t* wdir = winUtf8ToWide(dir);
	wchar_t* wcmd = winUtf8ToWide(cmd);
	if (wdir == NULL || wcmd == NULL) {
		logAndExit("winUtf8ToWide() failed");
	}

	if (!CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, 0, NULL, wdir, &si, &pi)) {
		// TODO: log wcmd, wdir
		winLogErr(GetLastError());
		logAndExit("CreateProcess() failed");
	}

	if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
		logAndExit("WaitForSingleObject() failed");
	}

	DWORD exitCode;
	if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
		logAndExit("GetExitCodeProcess() failed");
	}
	if (exitCode == 0) {
		if (msg != NULL && strlen(msg) > 0) {
			printf("%s\n", msg);
		}
	} else {
		logAndExit("command failed");
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	free(wcmd);
	free(wdir);
}

#else

static void runCommand(const char* dir, const char* cmd, const char* msg) {
	int pipeStdin[2];
	if (pipe(pipeStdin) != 0) {
		logAndExit("pipe() failed");
	}

	pid_t pid = fork();
	if (pid == -1) {
		// fork failed
		logAndExit("fork() failed");
	} else if (pid == 0) {
		// inside child process

		if (dup2(pipeStdin[0], STDIN_FILENO) == -1) {
			logAndExit("dup2() failed");
		}
		if (close(pipeStdin[0]) || close(pipeStdin[1])) {
			logAndExit("close() failed");
		}

		if (chdir(dir)) {
			logAndExit("chdir() failed");
		}

		// TODO: avoid running shell here; parse string into args array and launch exe directly

		const char* exeFullname = "sh";
		const char* args[] = {exeFullname, NULL};
		int ret = execvp(exeFullname, (char**)args);
		if (ret) {
			logAndExit("execvp failed");
		}
	} else {
		// inside parent process

		// close read side of pipe
		close(pipeStdin[0]);

		const char* data = cmd;
		size_t dataLen = strlen(cmd);
		for (size_t numWritten = 0; numWritten < dataLen; ) {
			ssize_t ret = write(pipeStdin[1], data + numWritten, dataLen - numWritten);
			if (ret < 0) {
				logAndExit("write() failed");
			}
			numWritten += ret;
		}

		// TODO: collect stdout and stderr from child process and print when process exits
		//   so they aren't interleaved with output from other processes running concurrently.

		close(pipeStdin[1]);

		int wstatus;
		pid_t res = waitpid(pid, &wstatus, 0);
		if (res == -1) {
			logAndExit("waitpid failed");
		} else if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) {
			// success
			if (msg != NULL && strlen(msg) > 0) {
				printf("%s\n", msg);
			}
		} else {
			logAndExit("command failed");
		}
	}
}
#endif

static int lineReplaceEOL(line* l) {
	if (l->len == 0 || l->buff[l->len - 1] != '\n') {
		return 0;
	}
	--l->len;
	l->buff[l->len] = 0;
	if (l->len > 0 && l->buff[l->len - 1] == '\r') {
		--l->len;
		l->buff[l->len] = 0;
	}
	return 1;
}

static void jobRunner(void) {
	line l1 = {0};
	line l2 = {0};
	line l3 = {0};
	while (G_EXITRES == EXIT_SUCCESS) {
		l1.len = 0;
		l2.len = 0;
		l3.len = 0;
		int err = pthread_mutex_lock(&G_MUT);
		if (err) {
			logAndExit("failed to lock mutex");
		}
		int readLineSuccess = readLine(&l1);
		if (readLineSuccess) {
			readLineSuccess = readLine(&l2);
		}
		if (readLineSuccess) {
			readLineSuccess = readLine(&l3);
		}
		err = pthread_mutex_unlock(&G_MUT);
		if (err) {
			// still holding lock - log and exit immediately
			fputs("failed to unlock mutex\n", stderr);
			exit(EXIT_FAILURE);
		}

		if (!readLineSuccess) {
			// failed to read lines - error message should have been printed
			G_EXITRES = EXIT_FAILURE;
			return;
		}
		if (!lineReplaceEOL(&l1) || !lineReplaceEOL(&l2) || !lineReplaceEOL(&l3)) {
			// TODO: if there is extra data parsed at end without a final newline character then
			//   print message indicating there's incomplete data at end of parallel commands?
			return;
		}

		runCommand(l1.buff, l2.buff, l3.buff);
	}
}

#ifdef _WIN32
static unsigned __stdcall jobRunnerCB(void* arg) {
	UNUSED(arg);
	jobRunner();
	return 0;
}

static int startThread(HANDLE* pThread) {
	uintptr_t h = _beginthreadex(NULL, 0, jobRunnerCB, NULL, 0, NULL);
	if (h == 0) {
		fprintf(stderr, "_beginthreadex() failed\n");
		return 0;
	}
	*pThread = (HANDLE) h;
	return 1;
}

static int joinThread(HANDLE t) {
	DWORD result = WaitForSingleObject(t, INFINITE);
	if (result != WAIT_OBJECT_0) {
		fprintf(stderr, "WaitForSingleObject() failed with return val %lu\n", result);
		return 0;
	}
	CloseHandle(t);
	return 1;
}

static int get_nprocs(void) {
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwNumberOfProcessors;
}

#else
static void* jobRunnerCB(void* arg) {
	UNUSED(arg);
	jobRunner();
	return NULL;
}

static int startThread(pthread_t* t) {
	int err = pthread_create(t, NULL, jobRunnerCB, NULL);
	if (err) {
		fprintf(stderr, "pthread_create() failed with err %d\n", err);
		return 0;
	}
	return 1;
}

static int joinThread(pthread_t t) {
	int err = pthread_join(t, NULL);
	if (err) {
		fprintf(stderr, "pthread_join() failed with err %d\n", err);
		return 1;
	}
	return 1;
}
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
static int get_nprocs(void) {
	int count = 1;
	size_t size = sizeof(count);
	if (sysctlbyname("hw.ncpu", &count, &size, NULL, 0)) {
		return 1;
	}
	return count;
}
#endif

int main(int argc, const char* argv[]) {
	// TODO: parse args and allow user to over-ride number of concurrent jobs
	// TODO: allow user to specify the command to use on linux. ie, "sh"
	UNUSED(argc);
	UNUSED(argv);

#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif

	int nprocs = get_nprocs();
	if (nprocs <= 0) {
		fprintf(stderr, "error: get_nprocs() returned %d\n", nprocs);
		exit(EXIT_FAILURE);
	}
	int err = pthread_mutex_init(&G_MUT, NULL);
	if (err) {
		fprintf(stderr, "pthread_mutex_init() failed with err %d\n", err);
		exit(EXIT_FAILURE);
	}
	pthread_t* t = malloc(sizeof(pthread_t) * nprocs);
	if (t == NULL) {
		fprintf(stderr, "malloc() failed\n");
		exit(EXIT_FAILURE);
	}
	int threadsCreated = 0;
	for (; threadsCreated < nprocs; ++threadsCreated) {
		if (!startThread(&t[threadsCreated])) {
			if (threadsCreated <= 0) {
				G_EXITRES = EXIT_FAILURE;
			}
			break;
		}
	}
	for (int i = 0; i < threadsCreated; ++i) {
		if (!joinThread(t[i])) {
			G_EXITRES = EXIT_FAILURE;
			break;
		}
	}
	// TODO: If exit is failure, signal child processes to terminate and wait for them to finish/exit before exiting.
	//   This is better in the case that a child process would normally run for a long time but a failure has occurred
	//   so it should just stop asap.
	exit(G_EXITRES);
}
