/*
 * Copyright 2018-2019 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifdef __linux__
#define _XOPEN_SOURCE 700
#endif

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
typedef int recvres;
#else
#define OPASOCKLOGERR() LOGSYSERRNO()
#define closesocket close
typedef ssize_t recvres;
#endif


// this is here for compiling with MSVC and targeting older versions of windows
#ifndef IN6ADDR_LOOPBACK_INIT
#define IN6ADDR_LOOPBACK_INIT {{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}}
static const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
#endif


void opasockInit(opasock* s) {
	s->sid = SOCKID_NONE;
}

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
}

int opasockIsLoopback(const opasock* s) {
	struct sockaddr_storage addr;
	socklen_t addrLen = sizeof(addr);
	// note: if socket was accepted from AcceptEx on win2k, then getpeername() will not work
	//   properly (returns no error, but struct is all 0's). Must use GetAcceptExSockaddrs()
	//   after calling AcceptEx()
	if (getpeername(s->sid, (struct sockaddr*)&addr, &addrLen) == 0) {
		if (addr.ss_family == AF_INET) {
			// ipv4
			uint32_t addr32 = ntohl(((struct sockaddr_in*)&addr)->sin_addr.s_addr);
			if ((addr32 & 0xFF000000) == 0x7f000000) {
				return 1;
			}
		} else if (addr.ss_family == AF_INET6) {
			// ipv6
			if (memcmp(&((struct sockaddr_in6*)&addr)->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) == 0) {
				// TODO: is this right? is loopback more than 1 address for ipv6?
				return 1;
			}
		}
	} else {
		OPASOCKLOGERR();
	}
	return 0;
}

void opasockConnect(opasock* s, const char* remoteAddr, uint16_t remotePort) {
	opasockConnectInternal(s, remoteAddr, remotePort, AF_UNSPEC, SOCK_STREAM, 0);
}

int opasockSetNonBlocking(opasock* s, int onOrOff) {
#ifdef _WIN32
	unsigned long val = onOrOff ? 1 : 0;
	if (ioctlsocket(s->sid, FIONBIO, &val)) {
		OPASOCKLOGERR();
		return OPA_ERR_INTERNAL;
	}
	return 0;
#else
	int flags = fcntl(s->sid, F_GETFL);
	if (flags == -1 || fcntl(s->sid, F_SETFL, onOrOff ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) == -1) {
		LOGSYSERRNO();
		return OPA_ERR_INTERNAL;
	}
	return 0;
#endif
}

/*
 * Return zero if peer has performed orderly shutdown and recv will not return any more bytes for the socket. Else
 * return non-zero. Note that a zero return value conclusively indicates that calling recv will never provide more
 * data. However a non-zero return code does not indicate for certain that the socket will provide more data for recv.
 * IE, the socket connection was lost without an orderly shutdown from the peer.
 */
int opasockMayRecvMore(opasock* s, int isNonBlocking) {
	char tmp[1];
#ifdef __linux__
	UNUSED(isNonBlocking);
	recvres result = recv(s->sid, tmp, 1, MSG_PEEK | MSG_DONTWAIT);
#else
	// cannot use MSG_DONTWAIT flag for recv
	if (!isNonBlocking) {
		int err = opasockSetNonBlocking(s, 1);
		if (err) {
			return 1;
		}
	}
	recvres result = recv(s->sid, tmp, 1, MSG_PEEK);
	if (!isNonBlocking) {
		int err = opasockSetNonBlocking(s, 0);
		if (err) {
			OPALOGERR("unable to return socket to blocking mode");
		}
	}
#endif
	// recv returns 0 when peer has performed an orderly shutdown; otherwise it returns -1 on error or number of bytes received
	// therefore, return non-zero if error occurs or 1 byte is available.
	return result != 0;
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
#elif defined(__APPLE__)
	ssize_t result = send(s->sid, buff, len, 0);
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
