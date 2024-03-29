/*
 * Copyright 2020 Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#include <stdio.h>
#include <string.h>

#if defined(__APPLE__) && (defined(OPA_SECTRANS) || (defined(OPA_MBEDTLS) && !defined(OPA_MBEDTLS_NO_MACOS_SYS_CERTS)))
#include <Security/SecureTransport.h>
#include <Security/Security.h>
#endif

#include "base64.h"
#include "opacore.h"
#ifdef OPA_MBEDTLS
#include "opatls/mbed.h"
#endif
#ifdef OPA_OPENSSL
#include "opatls/openssl.h"
#endif
#if defined(_WIN32) && defined(OPA_WINSCHAN)
#include "opatls/schan.h"
#endif
#if defined(__APPLE__) && defined(OPA_SECTRANS)
#include "opatls/sectrans.h"
#endif
#include "opatls/tlsutils.h"
#include "winutils.h"

static int tlsutilsParseCerts(char* certBuff, void* ctx, tlsutilsNextCertCB cbfunc) {
	int err = 0;
	while (!err) {
		const char* head1 = strstr(certBuff, "-----");
		if (head1 == NULL) {
			break;
		}
		char* tail1 = strstr(head1 + 5, "-----");
		if (tail1 == NULL) {
			break;
		}
		char* pemStart = tail1 + 5;

		const char* head2 = strstr(pemStart, "-----");
		if (head2 == NULL) {
			break;
		}
		char* tail2 = strstr(head2 + 5, "-----");
		if (tail2 == NULL) {
			break;
		}
		certBuff = tail2 + 5;

		if (!err) {
			char* dst = pemStart;
			for (const char* src = pemStart; src < head2; ++src) {
				if (*src != '\r' && *src != '\n' && *src != '\t' && *src != ' ') {
					*dst++ = *src;
				}
			}
			size_t decLen = base64DecodeLen(pemStart, dst - pemStart);
			if (!base64Decode(pemStart, dst - pemStart, pemStart)) {
				OPALOGERR("invalid base64 data in cert");
				err = OPA_ERR_INTERNAL;
			}
			if (!err) {
				// TODO: callback should include header? ie, "-----BEGIN CERTIFICATE-----"; should be null terminated?
				err = cbfunc(ctx, pemStart, decLen);
			}
		}
	}
	return err;
}

int tlsutilsIterateCerts(const char* file, void* ctx, tlsutilsNextCertCB cbfunc) {
	uint8_t* buff = NULL;
	size_t buffLen = 0;
	int err = opacoreReadFile(file, &buff, &buffLen);
	if (!err) {
		err = tlsutilsParseCerts((char*) buff, ctx, cbfunc);
	}
	opaZeroAndFree(buff, buffLen);
	return err;
}

static uint32_t hexVal(char ch) {
	if (ch <= '9' && ch >= '0') {
		return ch - '0';
	} else if (ch <= 'F' && ch >= 'A') {
		return ch - 'A' + 10;
	} else if (ch <= 'f' && ch >= 'a') {
		return ch - 'a' + 10;
	}
	return 0xFFFFFFFF;
}

int tlsutilsLoadPsk(const char* filename, opatlsPsk** ppPsk) {
	opatlsPsk* psk = NULL;
	uint8_t* buff = NULL;
	size_t buffLen = 0;
	int err = opacoreReadFile(filename, &buff, &buffLen);
	if (!err) {
		uint8_t* pos = memchr(buff, ':', buffLen);
		if (pos != NULL) {
			uint8_t* keyPos = pos + 1;
			for (const uint8_t* src = keyPos; src[0] != 0 && src[1] != 0; src += 2) {
				uint32_t uchar = (hexVal(src[0]) << 4) | hexVal(src[1]);
				if (uchar > 0xFF) {
					break;
				}
				*keyPos++ = (uint8_t) uchar;
			}
			size_t idLen = pos - buff;
			psk = opatlsPskNew(buff, idLen, pos + 1, keyPos - (pos + 1));
			if (psk == NULL) {
				err = OPA_ERR_NOMEM;
			}
		} else {
			OPALOGERR("psk is not stored properly. must be in format <id:key> where key is hex. example:\nopacli:0123456789abcdef4567456745674567");
			err = OPA_ERR_INTERNAL;
		}
	}
	if (err) {
		opatlsPskFree(psk);
	} else {
		*ppPsk = psk;
	}
	opaZeroAndFree(buff, buffLen);
	return err;
}

const opatlsLib* tlsutilsGetLib(const char* name) {
	const opatlsLib* lib = NULL;
	if (opaStrCmpNoCaseAscii(name, "mbed") == 0 || opaStrCmpNoCaseAscii(name, "mbedtls") == 0) {
		#ifdef OPA_MBEDTLS
			lib = &mbedLib;
		#endif
	} else if (opaStrCmpNoCaseAscii(name, "openssl") == 0) {
		#ifdef OPA_OPENSSL
			if (opensslLoadLib()) {
				lib = &opensslLib;
			}
		#endif
	} else if (opaStrCmpNoCaseAscii(name, "schan") == 0) {
		#if defined(_WIN32) && defined(OPA_WINSCHAN)
			if (winIsVerGTE(6, 1) && schanInit()) {
				lib = &schanLib;
			}
		#endif
	} else if (opaStrCmpNoCaseAscii(name, "sectrans") == 0) {
		#if defined(__APPLE__) && defined(OPA_SECTRANS)
			lib = &sectransLib;
		#endif
	}
	return lib;
}

const opatlsLib* tlsutilsGetDefaultLib(const char** libs, int numLibs) {
	const opatlsLib* lib = NULL;
	for (int i = 0; i < numLibs && libs[i] != NULL && lib == NULL; ++i) {
		lib = tlsutilsGetLib(libs[i]);
	}
	return lib;
}

#if defined(__APPLE__) && (defined(OPA_SECTRANS) || (defined(OPA_MBEDTLS) && !defined(OPA_MBEDTLS_NO_MACOS_SYS_CERTS)))

void osxRelease(CFTypeRef cf) {
	if (cf != NULL) {
		CFRelease(cf);
	}
}

int osxSecLogIfErr(const char* func, const char* filename, int line, const char* osxfunc, OSStatus errcode) {
	if (errcode == errSecSuccess) {
		return 0;
	}
	switch (errcode) {
		case errSSLWouldBlock:
			return OPA_ERR_WOULDBLOCK;
		case errSSLClosedNoNotify:
		case errSSLClosedGraceful:
		case errSSLClosedAbort:
			return OPA_ERR_EOF;
	}
	CFStringRef s = SecCopyErrorMessageString(errcode, NULL);
	if (s != NULL) {
		char tmp[256];
		const char* cstr = CFStringGetCStringPtr(s, kCFStringEncodingUTF8);
		if (cstr == NULL) {
			CFIndex convLen;
			CFStringGetBytes(s, CFRangeMake(0, CFStringGetLength(s)), kCFStringEncodingUTF8, '?', false, (UInt8*)tmp, sizeof(tmp) - 1, &convLen);
			tmp[convLen] = 0;
			cstr = tmp;
		}
		if (osxfunc == NULL) {
			opacoreLogErrf(func, filename, line, "os err %d: %s", errcode, cstr);
		} else {
			opacoreLogErrf(func, filename, line, "os err %d in %s(): %s", errcode, osxfunc, cstr);
		}
		CFRelease(s);
	} else {
		if (osxfunc == NULL) {
			opacoreLogErrf(func, filename, line, "os err %d", errcode);
		} else {
			opacoreLogErrf(func, filename, line, "os err %d in %s()", errcode, osxfunc);
		}
	}
	return OPA_ERR_INTERNAL;
}

#endif
