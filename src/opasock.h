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

typedef struct {
	sockid sid;
} opasock;


void opasockInit(opasock* s);
void opasockConnect(opasock* s, const char* remoteAddr, uint16_t remotePort);
int opasockIsLoopback(const opasock* s);
int opasockClose(opasock* s);
int opasockRecv(opasock* s, void* buff, size_t len, size_t* pNumRead);
int opasockSend(opasock* s, const void* buff, size_t len, size_t* pNumWritten);


#endif
