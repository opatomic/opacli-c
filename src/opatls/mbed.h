/*
 * Copyright 2020 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifndef MBED_H_
#define MBED_H_

#ifdef OPA_MBEDTLS

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"

#include "opatls/opatls.h"

#define MBEDCALL(func, ...) mbedLogIfErr(OPAFUNC, __FILE__, __LINE__, #func, func(__VA_ARGS__))
#define MBEDLOGERR(err) mbedLogIfErr(OPAFUNC, __FILE__, __LINE__, NULL, err)

typedef struct {
	mbedtls_ssl_config cfg;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt mbedcacert;
	mbedtls_x509_crt mbedclientcert;
	mbedtls_pk_context mbedclientkey;
	char isServer;
} mbedCfg;

typedef struct {
	mbedtls_ssl_context ctx;
	char fatalErr;
	char isServer;
	void* cbdata;
	const opatlsioStreamCBs* cbs;
} mbedConn;

extern const opatlsLib mbedLib;

int mbedLogIfErr(const char* func, const char* filename, int line, const char* libFuncName, int mbedResult);
const char* mbedGetDefaultCAPath(void);

int mbedCfgInit(mbedCfg* cfg, int isServer);
int mbedCfgAddCACertsFile(mbedCfg* cfg, const char* filepath);
int mbedCfgUseCert(mbedCfg* cfg, const char* cert, const char* key);
#define mbedCfgUseCertP12 opatlsReturnUnsupported
int mbedCfgVerifyPeer(mbedCfg* cfg, int verify);
int mbedCfgInitConn(mbedCfg* cfg, mbedConn* conn);
int mbedCfgClose(mbedCfg* cfg);

void mbedSetCallbackData(mbedConn* sd, void* cbdata, const opatlsioStreamCBs* cbs);
int mbedSetExpectedHost(mbedConn* sd, const char* host);
int mbedHandshake(mbedConn* sd);
int mbedRecv(mbedConn* sd, void* buff, size_t len, size_t* pNumRecv);
int mbedSend(mbedConn* sd, const void* buff, size_t len, size_t* pNumSent);
int mbedCloseNotify(mbedConn* sd);
void mbedClose(mbedConn* sd);

#endif

#endif
