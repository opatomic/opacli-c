/*
 * Copyright 2018-2019 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifndef OPASOCK_H_
#define OPASOCK_H_

#include <stddef.h>
#include <stdint.h>


#ifdef _WIN32
	#include <winsock2.h>
	typedef SOCKET sockid;
	#define SOCKID_NONE INVALID_SOCKET
#else
	typedef int sockid;
	#define SOCKID_NONE -1
#endif


sockid opasockConnect(const char* remoteAddr, uint16_t remotePort);
int opasockClose(sockid s);
int opasockRecv(sockid s, void* buff, size_t len, size_t* pNumRead);
int opasockSend(sockid s, const void* buff, size_t len, size_t* pNumWritten);


#endif
