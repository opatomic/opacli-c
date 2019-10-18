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


int opasockClose(sockid s) {
	if (closesocket(s)) {
		OPASOCKLOGERR();
		return OPA_ERR_INTERNAL;
	}
	return 0;
}

static sockid opasockConnectInternal(const char* remoteAddr, uint16_t remotePort, int aiFamily, int aiSockType, int aiFlags) {
	sockid s = SOCKID_NONE;
	char portStr[8];
	struct addrinfo hints = {.ai_flags = aiFlags, .ai_family = aiFamily, .ai_socktype = aiSockType, 0};
	struct addrinfo* allInfo = NULL;

	u32toa(remotePort, portStr, 10);
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
		if ((s = socket(i->ai_family, i->ai_socktype, i->ai_protocol)) != SOCKID_NONE) {
			if (connect(s, i->ai_addr, i->ai_addrlen) != 0) {
				//OPASOCKLOGERR();
				opasockClose(s);
				s = SOCKID_NONE;
				continue;
			}
			break;
		}
	}
	freeaddrinfo(allInfo);

	if (s == SOCKID_NONE) {
		OPALOGERRF("could not bind address; addr=%s port=%u", remoteAddr, remotePort);
	}

	return s;
}

sockid opasockConnect(const char* remoteAddr, uint16_t remotePort) {
	return opasockConnectInternal(remoteAddr, remotePort, AF_UNSPEC, SOCK_STREAM, 0);
}

int opasockRecv(sockid s, void* buff, size_t len, size_t* pNumRead) {
#ifdef _WIN32
	int result = recv(s, buff, len < (size_t) INT_MAX ? (int)len : INT_MAX, 0);
#else
	ssize_t result = recv(s, buff, len, 0);
#endif
	if (result < 0) {
		if (pNumRead != NULL) {
			*pNumRead = 0;
		}
		OPASOCKLOGERR();
		// TODO: convert err code
		return OPA_ERR_INTERNAL;
	}
	if (pNumRead != NULL) {
		*pNumRead = result;
	}
	return 0;
}

int opasockSend(sockid s, const void* buff, size_t len, size_t* pNumWritten) {
#ifdef _WIN32
	int result = send(s, buff, len < (size_t) INT_MAX ? (int)len : INT_MAX, 0);
#else
	ssize_t result = send(s, buff, len, MSG_NOSIGNAL);
#endif
	if (result < 0) {
		if (pNumWritten != NULL) {
			*pNumWritten = 0;
		}
		OPASOCKLOGERR();
		// TODO: convert err code
		return OPA_ERR_INTERNAL;
	}
	if (pNumWritten != NULL) {
		*pNumWritten = result;
	}
	return 0;
}
