/*
 * Copyright 2020 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#include <string.h>

#include "opacore.h"
#include "opatls/opatls.h"

struct opatlsConfig_s {
	char locked;
	unsigned long refs;
	const opatlsLib* lib;
};

struct opatlsPsk_s {
	unsigned int keyLen;
	unsigned int idLen;
	char data[];
};

opatlsPsk* opatlsPskNew(const void* id, size_t idLen, const void* key, size_t keyLen) {
	opatlsPsk* obj = OPAMALLOC(sizeof(opatlsPsk) + idLen + keyLen);
	if (obj != NULL) {
		obj->idLen = idLen;
		obj->keyLen = keyLen;
		memcpy(obj->data, id, idLen);
		memcpy(obj->data + idLen, key, keyLen);
	}
	return obj;
}

const char* opatlsPskGetKey(const opatlsPsk* psk) {
	return psk->data + psk->idLen;
}

size_t opatlsPskKeyLen(const opatlsPsk* psk) {
	return psk->keyLen;
}

const char* opatlsPskGetId(const opatlsPsk* psk) {
	return psk->data;
}

size_t opatlsPskIdLen(const opatlsPsk* psk) {
	return psk->idLen;
}

void opatlsPskFree(opatlsPsk* psk) {
	if (psk != NULL) {
		opaZeroAndFree(psk, sizeof(opatlsPsk) + psk->idLen + psk->keyLen);
	}
}

int opatlsReturnUnsupported(void* v, ...) {
	UNUSED(v);
	return OPA_ERR_UNSUPPORTED;
}

static int noneReturnErr(void* v, ...) {
	UNUSED(v);
	return OPA_ERR_INVSTATE;
}

#define noneCfgInit(...)           noneReturnErr(__VA_ARGS__)
#define noneCfgAddCACertsFile(...) noneReturnErr(__VA_ARGS__)
#define noneCfgUseCert(...)        noneReturnErr(__VA_ARGS__)
#define noneCfgUseCertP12(...)     noneReturnErr(__VA_ARGS__)
#define noneCfgVerifyPeer(...)     noneReturnErr(__VA_ARGS__)
#define noneCfgInitConn(...)       noneReturnErr(__VA_ARGS__)
#define noneCfgClose(...)          noneReturnErr(__VA_ARGS__)
#define noneSetCallbackData(...)   noneReturnErr(__VA_ARGS__)
#define noneSetExpectedHost(...)   noneReturnErr(__VA_ARGS__)
#define noneHandshake(...)         noneReturnErr(__VA_ARGS__)
#define noneRecv(...)              noneReturnErr(__VA_ARGS__)
#define noneSend(...)              noneReturnErr(__VA_ARGS__)
#define noneCloseNotify(...)       noneReturnErr(__VA_ARGS__)
#define noneClose(...)             noneReturnErr(__VA_ARGS__)

NEWLIB(none, void*, void*)

const opatlsLib noneLib = {
	"none",
	0,
	0,
	&none_CFG_FUNCS,
	&none_S_FUNCS
};


static const opatlsStateFuncs* opatlsStateGetFuncs(const opatlsState* ts) {
	OASSERT(ts->cfg != NULL && ts->cfg->lib != NULL);
	return ts->cfg->lib->stateFuncs;
}

void opatlsStateInit(opatlsState* ts) {
	memset(ts, 0, sizeof(opatlsState));
}

void opatlsStateSetCallbackData(opatlsState* ts, void* cbdata, const opatlsioStreamCBs* cbs) {
	opatlsStateGetFuncs(ts)->setCallbackData(ts->libData, cbdata, cbs);
}

int opatlsStateSetExpectedHost(opatlsState* ts, const char* expectedHostNameOnCert) {
	return opatlsStateGetFuncs(ts)->setExpectedHost(ts->libData, expectedHostNameOnCert);
}

static int opatlsStateHandshakeInternal(opatlsState* ts) {
	return opatlsStateGetFuncs(ts)->handshake(ts->libData);
}

int opatlsStateHandshake(opatlsState* ts) {
	int err = opatlsStateHandshakeInternal(ts);
	if (!err) {
		ts->hsDone = 1;
		//OPALOG("handshake complete");
	}
	return err;
}

int opatlsStateHandshakeCompleted(const opatlsState* ts) {
	return ts->hsDone;
}

int opatlsStateRead(opatlsState* ts, void* buff, size_t len, size_t* pNumRead) {
	int err = ts->hsDone ? 0 : opatlsStateHandshake(ts);
	if (!err) {
		err = opatlsStateGetFuncs(ts)->read(ts->libData, buff, len, pNumRead);
	}
	return err;
}

int opatlsStateWrite(opatlsState* ts, const void* buff, size_t len, size_t* pNumWritten) {
	int err = ts->hsDone ? 0 : opatlsStateHandshake(ts);
	if (!err) {
		err = opatlsStateGetFuncs(ts)->write(ts->libData, buff, len, pNumWritten);
	}
	return err;
}

int opatlsStateNotifyPeerClosing(opatlsState* ts) {
	if (!ts->hsDone) {
		return OPA_ERR_INVSTATE;
	}
	return opatlsStateGetFuncs(ts)->notifyPeerClosing(ts->libData);
}

void opatlsStateClear(opatlsState* ts) {
	if (ts == NULL || ts->cfg == NULL) {
		return;
	}

	opatlsStateGetFuncs(ts)->clear(ts->libData);
	if (ts->allocd) {
		OPAFREE(ts->libData);
	}
	opatlsConfigRemRef(ts->cfg);
	memset(ts, 0, sizeof(opatlsState));
}

static const opatlsCfgFuncs* opatlsCfgGetFuncs(const opatlsConfig* tc) {
	return tc->lib->cfgFuncs;
}

static void* opatlsCfgGetData(const opatlsConfig* tc) {
	return (void*) (tc + 1);
}

int opatlsConfigNew(const opatlsLib* lib, int isServer, opatlsConfig** pNewCfg) {
	if (lib == NULL) {
		return OPA_ERR_INVARG;
	}

	opatlsConfig* tc = OPACALLOC(1, sizeof(opatlsConfig) + lib->cfgDataLen);
	if (tc == NULL) {
		return OPA_ERR_NOMEM;
	}

	tc->lib = lib;
	tc->refs = 1;

	int err = lib->cfgFuncs->setup(opatlsCfgGetData(tc), isServer);
	if (!err) {
		*pNewCfg = tc;
	} else {
		OPAFREE(tc);
	}
	return err;
}

int opatlsConfigAddCACertsFile(opatlsConfig* tc, const char* filepath) {
	if (tc->locked) {
		return OPA_ERR_INVSTATE;
	}
	return opatlsCfgGetFuncs(tc)->addCACertsFile(opatlsCfgGetData(tc), filepath);
}

int opatlsConfigUseCert(opatlsConfig* tc, const char* certPath, const char* keyPath) {
	if (tc->locked) {
		return OPA_ERR_INVSTATE;
	}
	return opatlsCfgGetFuncs(tc)->useCert(opatlsCfgGetData(tc), certPath, keyPath);
}

int opatlsConfigUseCertP12(opatlsConfig* tc, const char* certPath, const char* pass) {
	if (tc->locked) {
		return OPA_ERR_INVSTATE;
	}
	return opatlsCfgGetFuncs(tc)->useCertP12(opatlsCfgGetData(tc), certPath, pass);
}

int opatlsConfigVerifyPeer(opatlsConfig* tc, int verify) {
	if (tc->locked) {
		return OPA_ERR_INVSTATE;
	}
	return opatlsCfgGetFuncs(tc)->verifyPeer(opatlsCfgGetData(tc), verify);
}

static void opatlsConfigClear(opatlsConfig* tc) {
	opatlsCfgGetFuncs(tc)->clear(opatlsCfgGetData(tc));
	memset(tc, 0, sizeof(opatlsConfig));
	OPAFREE(tc);
}

#ifdef OPA_NOTHREADS
#define ATOMIC_INC(v) (++(*(v)))
#define ATOMIC_DEC(v) (--(*(v)))
#else
#ifdef _MSC_VER
#define ATOMIC_INC(v) InterlockedIncrement((LONG volatile *) (v))
#define ATOMIC_DEC(v) InterlockedDecrement((LONG volatile *) (v))
#elif defined(__GNUC__)
#define ATOMIC_INC(v) __sync_add_and_fetch((v), 1)
#define ATOMIC_DEC(v) __sync_sub_and_fetch((v), 1)
#endif
#endif

void opatlsConfigAddRef(const opatlsConfig* tc) {
	if (tc != NULL) {
		long res = ATOMIC_INC(&((opatlsConfig*)tc)->refs);
		OASSERT(res > 0);
	}
}

void opatlsConfigRemRef(const opatlsConfig* tc) {
	if (tc != NULL) {
		long res = ATOMIC_DEC(&((opatlsConfig*)tc)->refs);
		OASSERT(res + 1 != 0);
		if (res == 0) {
			opatlsConfigClear((opatlsConfig*)tc);
		}
	}
}

int opatlsConfigSetupNewState(const opatlsConfig* tc, opatlsState* state, void* stateData) {
	int allocd = 0;
	if (stateData == NULL && tc->lib->stateDataLen > 0) {
		stateData = OPACALLOC(tc->lib->stateDataLen, 1);
		if (stateData == NULL) {
			return OPA_ERR_NOMEM;
		}
		allocd = 1;
	}
	int err = opatlsCfgGetFuncs(tc)->initState(opatlsCfgGetData(tc), stateData);
	if (!err) {
		if (!tc->locked) {
			// when a new opatlsState object is created, the config cannot change anymore because
			// the state object may refer back to the config object's data structures (see mbedtls_ssl_setup() docs).
			((opatlsConfig*)tc)->locked = 1;
		}
		opatlsConfigAddRef(tc);
		memset(state, 0, sizeof(opatlsState));
		state->allocd = allocd;
		state->cfg = tc;
		state->libData = stateData;
	} else {
		if (allocd) {
			OPAFREE(stateData);
		}
	}
	return err;
}
