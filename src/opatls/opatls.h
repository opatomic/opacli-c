/*
 * Copyright 2020 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifndef OPATLS_H_
#define OPATLS_H_


#include <stddef.h>


// try to read len bytes. return number of bytes read into buff. return 0 to indicate EWOULDBLOCK/CLOSED/error
typedef int (*opatlsioRead)(void* state, void* buff, size_t numToRead, size_t* pNumRead);
// try to write len bytes. return number of bytes written from buff. return 0 to indicate EWOULDBLOCK/CLOSED/error
typedef int (*opatlsioWrite)(void* state, const void* buff, size_t numToWrite, size_t* pNumWritten);

typedef struct {
	opatlsioRead read;
	opatlsioWrite write;
} opatlsioStreamCBs;


typedef struct opatlsPsk_s opatlsPsk;

opatlsPsk* opatlsPskNew(const void* id, size_t idLen, const void* key, size_t keyLen);
const char* opatlsPskGetKey(const opatlsPsk* psk);
size_t opatlsPskKeyLen(const opatlsPsk* psk);
const char* opatlsPskGetId(const opatlsPsk* psk);
size_t opatlsPskIdLen(const opatlsPsk* psk);
void opatlsPskFree(opatlsPsk* psk);


// This macro is here to define functions that accept void* type and then cast to appropriate type.
// The functions can probably just be cast instead. However, C spec states that it is undefined behavior
// because the function parameters are not compatible?
#define NEWLIB(name, cfgType, sType) \
static void name##_TC_SetCallbackData(void* ts, void* cbdata, const opatlsioStreamCBs* cbs) { \
	name##SetCallbackData((sType) ts, cbdata, cbs); \
} \
static int name##_TC_SetExpectedHost(void* ts, const char* expectedHostNameOnCert) { \
	return name##SetExpectedHost((sType) ts, expectedHostNameOnCert); \
} \
static int name##_TC_Handshake(void* ts) { \
	return name##Handshake((sType) ts); \
} \
static int name##_TC_Read(void* ts, void* buff, size_t len, size_t* pNumRead) { \
	return name##Recv((sType) ts, buff, len, pNumRead); \
} \
static int name##_TC_Write(void* ts, const void* buff, size_t len, size_t* pNumWritten) { \
	return name##Send((sType) ts, buff, len, pNumWritten); \
} \
static int name##_TC_CloseNotify(void* ts) { \
	return name##CloseNotify((sType) ts); \
} \
static void name##_TC_Close(void* ts) { \
	name##Close((sType) ts); \
} \
const opatlsStateFuncs name##_S_FUNCS = {name##_TC_SetCallbackData, name##_TC_SetExpectedHost, name##_TC_Handshake, name##_TC_Read, name##_TC_Write, name##_TC_CloseNotify, name##_TC_Close};\
static int name##_TC_CfgSetup(void* ts, int isServer) { \
	return name##CfgInit((cfgType) ts, isServer); \
} \
static int name##_TC_CfgAddCACertsFile(void* ts, const char* filepath) { \
	return name##CfgAddCACertsFile((cfgType) ts, filepath); \
} \
static int name##_TC_CfgUseCert(void* ts, const char* certPath, const char* keyPath) { \
	return name##CfgUseCert((cfgType) ts, certPath, keyPath); \
} \
static int name##_TC_CfgUseCertP12(void* ts, const char* certPath, const char* pass) { \
	return name##CfgUseCertP12((cfgType) ts, certPath, pass); \
} \
static int name##_TC_CfgVerifyPeer(void* ts, int verify) { \
	return name##CfgVerifyPeer((cfgType) ts, verify); \
} \
static int name##_TC_CfgInitState(void* ts, void* state) { \
	return name##CfgInitConn((cfgType) ts, (sType) state); \
} \
static void name##_TC_CfgClose(void* ts) { \
	name##CfgClose((cfgType) ts); \
} \
const opatlsCfgFuncs name##_CFG_FUNCS = {name##_TC_CfgSetup, name##_TC_CfgAddCACertsFile, name##_TC_CfgUseCert, name##_TC_CfgUseCertP12, name##_TC_CfgVerifyPeer, name##_TC_CfgInitState, name##_TC_CfgClose};\


typedef struct {
	int (*setup)(void* tc, int isServer);
	int (*addCACertsFile)(void* tc, const char* filepath);
	int (*useCert)(void* tc, const char* certPath, const char* keyPath);
	int (*useCertP12)(void* tc, const char* certPath, const char* pass);
	int (*verifyPeer)(void* tc, int verify);
	int (*initState)(void* tc, void* state);
	void (*clear)(void* tc);
} opatlsCfgFuncs;

typedef struct {
	void (*setCallbackData)(void* ts, void* cbdata, const opatlsioStreamCBs* cbs);
	int (*setExpectedHost)(void* ts, const char* expectedHostNameOnCert);
	int (*handshake)(void* ts);
	int (*read)(void* ts, void* buff, size_t len, size_t* pNumRead);
	int (*write)(void* ts, const void* buff, size_t len, size_t* pNumWritten);
	int (*notifyPeerClosing)(void* ts);
	void (*clear)(void* ts);
} opatlsStateFuncs;

typedef struct {
	const char* name;
	size_t cfgDataLen;
	size_t stateDataLen;
	const opatlsCfgFuncs* cfgFuncs;
	const opatlsStateFuncs* stateFuncs;
} opatlsLib;

typedef struct {
	char hsDone;
	char allocd;
	const opatlsLib* lib;
	void* libData;
} opatlsState;


int opatlsReturnUnsupported(void* v, ...);

void opatlsStateInit(opatlsState* ts);
void opatlsStateSetCallbackData(opatlsState* ts, void* cbdata, const opatlsioStreamCBs* cbs);
int opatlsStateSetExpectedHost(opatlsState* ts, const char* expectedHostNameOnCert);
int opatlsStateHandshake(opatlsState* ts);
int opatlsStateHandshakeCompleted(const opatlsState* ts);
int opatlsStateRead(opatlsState* ts, void* buff, size_t len, size_t* pNumRead);
int opatlsStateWrite(opatlsState* ts, const void* buff, size_t len, size_t* pNumWritten);
int opatlsStateNotifyPeerClosing(opatlsState* ts);
void opatlsStateClear(opatlsState* ts);


typedef struct {
	char allocd;
	const opatlsLib* lib;
	void* libData2;
} opatlsConfig;

void opatlsConfigInit(opatlsConfig* tc);
int opatlsConfigSetup(opatlsConfig* tc, const opatlsLib* lib, void* libData, int isServer);
int opatlsConfigAddCACertsFile(opatlsConfig* tc, const char* filepath);
int opatlsConfigUseCert(opatlsConfig* tc, const char* certPath, const char* keyPath);
int opatlsConfigUseCertP12(opatlsConfig* tc, const char* certPath, const char* pass);
int opatlsConfigVerifyPeer(opatlsConfig* tc, int verify);
void opatlsConfigClear(opatlsConfig* tc);

int opatlsConfigSetupNewState(opatlsConfig* tc, opatlsState* state, void* stateData);


#endif
