/*
 * Copyright 2020 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifndef TLSUTILS_H_
#define TLSUTILS_H_

#include <stdint.h>

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

#include "opatls.h"

typedef int (*tlsutilsNextCertCB)(void* ctx, const void* buff, size_t len);

int tlsutilsReadFile(const char* path, uint8_t** pBuff, size_t* pLen);
int tlsutilsIterateCerts(const char* file, void* ctx, tlsutilsNextCertCB cbfunc);
int tlsutilsLoadPsk(const char* filename, opatlsPsk** ppPsk);
const opatlsLib* tlsutilsGetDefaultLib(void);
const opatlsLib* tlsutilsGetLib(const char* name);

#ifdef __APPLE__
#define OSXSECOP(func, ...) osxSecLogIfErr(OPAFUNC, __FILE__, __LINE__, #func, func(__VA_ARGS__))
void osxRelease(CFTypeRef cf);
int osxSecLogIfErr(const char* func, const char* filename, int line, const char* osxfunc, OSStatus errcode);
#endif

#endif
