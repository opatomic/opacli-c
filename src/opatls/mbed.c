/*
 * Copyright 2020 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#ifdef OPA_MBEDTLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#endif

#if defined(__APPLE__) && !defined(OPA_MBEDTLS_NO_MACOS_SYS_CERTS)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecureTransport.h>
#include <Security/Security.h>
#endif

#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"

#include "opacore.h"
#include "opatls/mbed.h"
#include "opatls/tlsutils.h"


#define MBED_SYSCERTSTORE_PREFIX "sys:"
#define BLKERR(e) ((e) == MBEDTLS_ERR_SSL_WANT_READ || (e) == MBEDTLS_ERR_SSL_WANT_WRITE || (e) == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS || (e) == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)


int mbedLogIfErr(const char* func, const char* filename, int line, const char* libFuncName, int mbedResult) {
	if (mbedResult >= 0) {
		return 0;
	}
	char tmpbuff[256];
	mbedtls_strerror(mbedResult, tmpbuff, sizeof(tmpbuff));
	if (libFuncName == NULL) {
		opacoreLogErrf(func, filename, line, "mbedtls err %d: %s", mbedResult, tmpbuff);
	} else {
		opacoreLogErrf(func, filename, line, "mbedtls err %d in %s(): %s", mbedResult, libFuncName, tmpbuff);
	}
	return OPA_ERR_INTERNAL;
}

static int opasockTLSReadCB(void* ctx, unsigned char* buf, size_t len) {
	mbedConn* conn = (mbedConn*) ctx;
	size_t numRead = 0;
	// note: limiting len to INT_MAX because return type of this function is int
	int err = conn->cbs->read(conn->cbdata, buf, len > INT_MAX ? INT_MAX : len, &numRead);
	if (err) {
		if (err == OPA_ERR_WOULDBLOCK) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		} else if (err == OPA_ERR_EOF) {
			return 0;
		}
		// TODO: detect/return MBEDTLS_ERR_NET_CONN_RESET when appropriate? (see mbedtls_net_recv() in net_sockets.c)
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	return numRead;
}

static int opasockTLSWriteCB(void* ctx, const unsigned char* buf, size_t len) {
	mbedConn* conn = (mbedConn*) ctx;
	size_t numWritten = 0;
	// note: limiting len to INT_MAX because return type of this function is int
	int err = conn->cbs->write(conn->cbdata, buf, len > INT_MAX ? INT_MAX : len, &numWritten);
	if (err) {
		if (err == OPA_ERR_WOULDBLOCK) {
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}
		// TODO: detect/return MBEDTLS_ERR_NET_CONN_RESET when appropriate? (see mbedtls_net_send() in net_sockets.c)
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return numWritten;
}

#if defined(_WIN32) || (defined(__APPLE__) && !defined(OPA_MBEDTLS_NO_MACOS_SYS_CERTS))
static int startsWith(const char* str, const char* prefix) {
	size_t slen = strlen(str);
	size_t prelen = strlen(prefix);
	return slen >= prelen && memcmp(str, prefix, prelen) == 0;
}
#endif

#ifdef _WIN32
static int mbedtlsAddWinSysCerts(mbedtls_x509_crt* chain, const char* systemStoreName) {
	// systemStoreName should be ROOT?
	// testing on win2k: https://www.techrepublic.com/article/using-the-certificate-mmc-snap-in-with-windows-2000-pro/
	int err = 0;
	int attempted = 0;
	int added = 0;
	HCERTSTORE store = CertOpenSystemStore((HCRYPTPROV) NULL, systemStoreName);
	if (store == NULL) {
		LOGWINERR();
		err = OPA_ERR_INTERNAL;
	}
	PCCERT_CONTEXT cert = NULL;
	while (!err) {
		cert = CertEnumCertificatesInStore(store, cert);
		if (cert == NULL) {
			DWORD errcode = GetLastError();
			if (errcode != ERROR_NO_MORE_FILES && HRESULT_FROM_WIN32(errcode) != CRYPT_E_NOT_FOUND) {
				LOGWINERRCODE(errcode);
				err = OPA_ERR_INTERNAL;
			}
			break;
		}
		++attempted;
		// note: this might fail. TODO: check error code and print message? maybe only for verbose mode? some certs could be expired
		int mbederr = mbedtls_x509_crt_parse(chain, cert->pbCertEncoded, cert->cbCertEncoded);
		if (!mbederr) {
			++added;
		}
	}
	//OPALOGF("attempted=%d; added=%d", attempted, added);
	if (store != NULL && !CertCloseStore(store, 0)) {
		LOGWINERR();
	}
	return err;
}
#endif

#if defined(__APPLE__) && !defined(OPA_MBEDTLS_NO_MACOS_SYS_CERTS)
static int mbedtlsAddOSXKeychainCerts(mbedtls_x509_crt* chain, const char* path) {
	int err = 0;
	int attempted = 0;
	int added = 0;
	SecKeychainRef kc = NULL;
	CFArrayRef kcs = NULL;
	CFMutableDictionaryRef copyOptions = NULL;
	CFArrayRef matches = NULL;
	if (!err) {
		// Mac OSX root certs path: "/System/Library/Keychains/SystemRootCertificates.keychain"
		err = OSXSECOP(SecKeychainOpen, path, &kc);
	}
	if (!err) {
		kcs = CFArrayCreate(NULL, (const void **)&kc, 1, NULL);
		if (kcs == NULL) {
			err = OPA_ERR_NOMEM;
		}
	}
	if (!err) {
		copyOptions = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
		if (copyOptions == NULL) {
			err = OPA_ERR_NOMEM;
		}
	}
	// https://developer.apple.com/documentation/security/keychain_services/keychain_items/searching_for_keychain_items
	if (!err) {
		CFDictionarySetValue(copyOptions, kSecClass, kSecClassCertificate);
		CFDictionarySetValue(copyOptions, kSecReturnRef, kCFBooleanTrue);
		CFDictionarySetValue(copyOptions, kSecMatchLimit, kSecMatchLimitAll);
		CFDictionarySetValue(copyOptions, kSecMatchSearchList, kcs);
	}
	if (!err) {
		err = OSXSECOP(SecItemCopyMatching, copyOptions, (CFTypeRef*) &matches);
	}
	if (!err) {
		CFIndex count = CFArrayGetCount(matches);
		attempted = count;
		for (CFIndex i = 0; i < count; i++) {
			SecCertificateRef cert = (SecCertificateRef) CFArrayGetValueAtIndex(matches, i);
			CFDataRef copy = SecCertificateCopyData(cert);
			if (copy != NULL) {
				// note: this might fail. TODO: check error code and print message?
				int mbederr = mbedtls_x509_crt_parse_der(chain, CFDataGetBytePtr(copy), CFDataGetLength(copy));
				if (!mbederr) {
					++added;
				}
				osxRelease(copy);
			}
		}
	}
	//OPALOGF("attempted=%d; added=%d", attempted, added);
	osxRelease(kc);
	osxRelease(kcs);
	osxRelease(copyOptions);
	osxRelease(matches);
	return err;
}
#endif

const char* mbedGetDefaultCAPath(void) {
#ifdef __linux__
	// TODO: add more paths to check?
	//    https://github.com/openssl/openssl/issues/7481#issuecomment-449299263
	if (access("/etc/ssl/certs/ca-certificates.crt", F_OK) != -1) {
		// note: defaulting to this path is a potential security problem if the file can be modified by untrusted entities
		return "/etc/ssl/certs/ca-certificates.crt";
	}
	return NULL;
#elif defined(_WIN32)
	// which windows system store to use here? why ROOT rather than CA? some cases that need to use several combined at once?
	return MBED_SYSCERTSTORE_PREFIX "ROOT";
#elif defined(__APPLE__) && !defined(OPA_MBEDTLS_NO_MACOS_SYS_CERTS)
	return MBED_SYSCERTSTORE_PREFIX "/System/Library/Keychains/SystemRootCertificates.keychain";
#else
	return NULL;
#endif
}

int mbedCfgInit(mbedCfg* cfg, int isServer) {
	mbedtls_ssl_config_init(&cfg->cfg);
	mbedtls_ctr_drbg_init(&cfg->ctr_drbg);
	mbedtls_entropy_init(&cfg->entropy);
	mbedtls_x509_crt_init(&cfg->mbedcacert);
	mbedtls_x509_crt_init(&cfg->mbedclientcert);
	mbedtls_pk_init(&cfg->mbedclientkey);

	mbedtls_ssl_conf_ca_chain(&cfg->cfg, &cfg->mbedcacert, NULL);
	int err = MBEDCALL(mbedtls_ctr_drbg_seed, &cfg->ctr_drbg, mbedtls_entropy_func, &cfg->entropy, NULL, 0);
	if (!err) {
		err = MBEDCALL(mbedtls_ssl_config_defaults, &cfg->cfg, isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	}
	if (!err) {
		mbedtls_ssl_conf_rng(&cfg->cfg, mbedtls_ctr_drbg_random, &cfg->ctr_drbg);
		cfg->isServer = isServer;
	}
	return err;
}

static int addnextcert(void* ctx, const void* buff, size_t len) {
	mbedCfg* cfg = ctx;
	int mbederr = mbedtls_x509_crt_parse_der(&cfg->mbedcacert, buff, len);
	if (mbederr) {
		// TODO: handle more error codes here?
		if (mbederr == MBEDTLS_ERR_X509_ALLOC_FAILED) {
			return OPA_ERR_NOMEM;
		}
		//OPALOG("err when adding CA cert");
	}
	return 0;
}

int mbedCfgAddCACertsFile(mbedCfg* cfg, const char* filepath) {
#ifdef _WIN32
	if (startsWith(filepath, MBED_SYSCERTSTORE_PREFIX)) {
		return mbedtlsAddWinSysCerts(&cfg->mbedcacert, filepath + strlen(MBED_SYSCERTSTORE_PREFIX));
	}
#endif
#if defined(__APPLE__) && !defined(OPA_MBEDTLS_NO_MACOS_SYS_CERTS)
	if (startsWith(filepath, MBED_SYSCERTSTORE_PREFIX)) {
		return mbedtlsAddOSXKeychainCerts(&cfg->mbedcacert, filepath + strlen(MBED_SYSCERTSTORE_PREFIX));
	}
#endif
	// TODO: log if some certs were not parsed properly? (this can indicate that mbedtls was not compiled with support
	//   for things such as sha-1, sha-512, specific ec curves, etc)

	// note: mbedtls_x509_crt_parse_file() is slow in mbedtls now. see https://github.com/ARMmbed/mbedtls/issues/4814
	return tlsutilsIterateCerts(filepath, cfg, addnextcert);
}

int mbedCfgUseCert(mbedCfg* cfg, const char* cert, const char* key) {
	int err = 0;
	if (cert != NULL && !err) {
		err = MBEDCALL(mbedtls_x509_crt_parse_file, &cfg->mbedclientcert, cert);
	}
	if (key != NULL && !err) {
		err = MBEDCALL(mbedtls_pk_parse_keyfile, &cfg->mbedclientkey, key, NULL);
	}
	if (!err) {
		err = MBEDCALL(mbedtls_ssl_conf_own_cert, &cfg->cfg, &cfg->mbedclientcert, &cfg->mbedclientkey);
	}
	return err;
}

int mbedCfgVerifyPeer(mbedCfg* cfg, int verify) {
	// TODO: test all clients connecting to a server with MBEDTLS_SSL_VERIFY_OPTIONAL enabled
	//mbedtls_ssl_conf_authmode(&cfg->cfg, verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_authmode(&cfg->cfg, verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
	return 0;
}

int mbedCfgInitConn(mbedCfg* cfg, mbedConn* conn) {
	memset(conn, 0, sizeof(mbedConn));
	conn->isServer = cfg->isServer;
	mbedtls_ssl_init(&conn->ctx);
	mbedtls_ssl_set_bio(&conn->ctx, conn, opasockTLSWriteCB, opasockTLSReadCB, NULL);
	return MBEDCALL(mbedtls_ssl_setup, &conn->ctx, &cfg->cfg);
}

int mbedCfgClose(mbedCfg* cfg) {
	mbedtls_ssl_config_free(&cfg->cfg);
	mbedtls_ctr_drbg_free(&cfg->ctr_drbg);
	mbedtls_entropy_free(&cfg->entropy);
	mbedtls_x509_crt_free(&cfg->mbedcacert);
	mbedtls_x509_crt_free(&cfg->mbedclientcert);
	mbedtls_pk_free(&cfg->mbedclientkey);
	return 0;
}

void mbedSetCallbackData(mbedConn* sd, void* cbdata, const opatlsioStreamCBs* cbs) {
	sd->cbdata = cbdata;
	sd->cbs = cbs;
}

int mbedSetExpectedHost(mbedConn* sd, const char* host) {
	return MBEDCALL(mbedtls_ssl_set_hostname, &sd->ctx, host);
}

int mbedHandshake(mbedConn* sd) {
	//int completed = 0;
	int err = sd->fatalErr ? OPA_ERR_INVSTATE : 0;
	if (!err) {
		int mbederr = mbedtls_ssl_handshake(&sd->ctx);
		if (mbederr == 0) {
			//completed = 1;
		} else if (BLKERR(mbederr)) {
			err = OPA_ERR_WOULDBLOCK;
		} else {
			sd->fatalErr = 1;
			err = MBEDLOGERR(mbederr);
		}

		// TODO: move this logging code somewhere else?
		if ((mbederr == 0 && !sd->isServer) || mbederr == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
			uint32_t flags = mbedtls_ssl_get_verify_result(&sd->ctx);
			if (flags != 0) {
				char tmpbuff[256];
				mbedtls_x509_crt_verify_info(tmpbuff, sizeof(tmpbuff), "  ", flags);
				opa_fprintf(stderr, "Peer verification problems:\n%s", tmpbuff);
				if (mbederr == 0) {
					opa_fprintf(stderr, "--no-verify-peer requested; ignoring these problems\n");
				}
			}
		}
	}
	//if (pCompleted != NULL) {
	//	*pCompleted = completed;
	//}
	return err;
}

int mbedRecv(mbedConn* sd, void* buff, size_t len, size_t* pNumRecv) {
	size_t count = 0;
	int err = sd->fatalErr ? OPA_ERR_INVSTATE : 0;
	if (!err) {
		int mbedres = mbedtls_ssl_read(&sd->ctx, buff, len);
		if (mbedres > 0) {
			count = mbedres;
		} else if (BLKERR(mbedres)) {
			err = OPA_ERR_WOULDBLOCK;
		} else if (mbedres == 0 || mbedres == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			// TODO: if mbedtls_ssl_read() returns 0 then must stop using the context (see mbedtls api docs)
			err = OPA_ERR_EOF;
		} else {
			sd->fatalErr = 1;
			err = MBEDLOGERR(mbedres);
		}
	}
	if (pNumRecv != NULL) {
		*pNumRecv = count;
	}
	return err;
}

int mbedSend(mbedConn* sd, const void* buff, size_t len, size_t* pNumSent) {
	size_t count = 0;
	int err = sd->fatalErr ? OPA_ERR_INVSTATE : 0;
	if (!err) {
		int mbedres = mbedtls_ssl_write(&sd->ctx, buff, len);
		if (mbedres >= 0) {
			count = mbedres;
		} else if (BLKERR(mbedres)) {
			err = OPA_ERR_WOULDBLOCK;
		} else {
			sd->fatalErr = 1;
			err = MBEDLOGERR(mbedres);
		}
	}
	if (pNumSent != NULL) {
		*pNumSent = count;
	}
	return err;
}

int mbedCloseNotify(mbedConn* sd) {
	//int notified = 0;
	int err = sd->fatalErr ? OPA_ERR_INVSTATE : 0;
	if (!err) {
		int mbederr = mbedtls_ssl_close_notify(&sd->ctx);
		if (mbederr == 0) {
			//notified = 1;
		} else if (mbederr == MBEDTLS_ERR_SSL_WANT_READ || mbederr == MBEDTLS_ERR_SSL_WANT_WRITE) {
			err = OPA_ERR_WOULDBLOCK;
		} else {
			sd->fatalErr = 1;
			err = MBEDLOGERR(mbederr);
		}
	}
	//if (pNotified != NULL) {
	//	*pNotified = notified;
	//}
	return err;
}

void mbedClose(mbedConn* sd) {
	mbedtls_ssl_free(&sd->ctx);
}

NEWLIB(mbed, mbedCfg*, mbedConn*)

const opatlsLib mbedLib = {
	"mbedtls",
	sizeof(mbedCfg),
	sizeof(mbedConn),
	&mbed_CFG_FUNCS,
	&mbed_S_FUNCS
};

#else

// this is here to get rid of a warning for "an empty translation unit"
typedef int compilerWarningFix;

#endif
