/*
 * Copyright 2018-2019 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#if (_WIN32_WINNT < 0x0501)
// by including wspiapi.h, getaddrinfo() and related functions will be supported on win2k even though they
//  are not available in the OS
//  See MS docs for getaddrinfo(): https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo
// note: wspiapi.h needs to be included after ws2tcpip.h
#include <wspiapi.h>
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "opacore.h"
#include "opasock.h"

#ifdef _WIN32
#define OPASOCKLOGERR() LOGWINERRCODE(WSAGetLastError())
#else
#ifdef __APPLE__
// TODO: since apple doesn't have MSG_NOSIGNAL, should use signal(SIGPIPE, SIG_IGN) instead?
#define MSG_NOSIGNAL 0
#endif
#define OPASOCKLOGERR() LOGSYSERRNO()
#define closesocket close
#endif


int opasockClose(opasock* s) {
	if (s->sid != SOCKID_NONE && closesocket(s->sid)) {
		OPASOCKLOGERR();
		return OPA_ERR_INTERNAL;
	}
	s->sid = SOCKID_NONE;
	return 0;
}

static void opasockConnectInternal(opasock* s, const char* remoteAddr, uint16_t remotePort, int aiFamily, int aiSockType, int aiFlags) {
	s->sid = SOCKID_NONE;
	char portStr[8];
	struct addrinfo hints = {.ai_flags = aiFlags, .ai_family = aiFamily, .ai_socktype = aiSockType, 0};
	struct addrinfo* allInfo = NULL;

	snprintf(portStr, sizeof(portStr), "%d", remotePort);
	int err = getaddrinfo(remoteAddr, portStr, &hints, &allInfo);
	if (err) {
		#ifdef _WIN32
			// gai_strerror() is not thread safe on windows; use WSAGetLastError() instead
			OPASOCKLOGERR();
		#else
			OPALOGERRF("getaddrinfo() returned err %d: %s", err, gai_strerror(err));
		#endif
	}

	for (struct addrinfo* i = allInfo; i != NULL; i = i->ai_next) {
		if ((s->sid = socket(i->ai_family, i->ai_socktype, i->ai_protocol)) != SOCKID_NONE) {
			if (connect(s->sid, i->ai_addr, i->ai_addrlen) != 0) {
				//OPASOCKLOGERR();
				opasockClose(s);
				continue;
			}
			break;
		}
	}
	freeaddrinfo(allInfo);

	if (s->sid == SOCKID_NONE) {
		OPALOGERRF("could not bind address; addr=%s port=%u", remoteAddr, remotePort);
	}
}

void opasockConnect(opasock* s, const char* remoteAddr, uint16_t remotePort) {
	opasockConnectInternal(s, remoteAddr, remotePort, AF_UNSPEC, SOCK_STREAM, 0);
}

int opasockRecv(opasock* s, void* buff, size_t len, size_t* pNumRead) {
#ifdef _WIN32
	int result = recv(s->sid, buff, len < (size_t) INT_MAX ? (int)len : INT_MAX, 0);
#else
	ssize_t result = recv(s->sid, buff, len, 0);
#endif
	if (result <= 0) {
		if (pNumRead != NULL) {
			*pNumRead = 0;
		}
		if (result == 0) {
			return OPA_ERR_EOF;
		}
#ifdef _WIN32
		int wsaErr = WSAGetLastError();
		if (wsaErr == WSAEWOULDBLOCK) {
			return OPA_ERR_WOULDBLOCK;
		}
#else
		int syserr = errno;
		if (syserr == EAGAIN || syserr == EWOULDBLOCK) {
			return OPA_ERR_WOULDBLOCK;
		}
#endif
		OPASOCKLOGERR();
		// TODO: convert more err codes
		return OPA_ERR_INTERNAL;
	}
	if (pNumRead != NULL) {
		*pNumRead = result;
	}
	return 0;
}

int opasockSend(opasock* s, const void* buff, size_t len, size_t* pNumWritten) {
#ifdef _WIN32
	int result = send(s->sid, buff, len < (size_t) INT_MAX ? (int)len : INT_MAX, 0);
#else
	ssize_t result = send(s->sid, buff, len, MSG_NOSIGNAL);
#endif
	if (result < 0) {
		if (pNumWritten != NULL) {
			*pNumWritten = 0;
		}
#ifdef _WIN32
		int wsaErr = WSAGetLastError();
		if (wsaErr == WSAEWOULDBLOCK) {
			return OPA_ERR_WOULDBLOCK;
		}
#else
		int syserr = errno;
		if (syserr == EAGAIN || syserr == EWOULDBLOCK) {
			return OPA_ERR_WOULDBLOCK;
		}
#endif
		OPASOCKLOGERR();
		// TODO: convert more err codes
		return OPA_ERR_INTERNAL;
	}
	if (pNumWritten != NULL) {
		*pNumWritten = result;
	}
	return 0;
}
