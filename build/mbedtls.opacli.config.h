/**
 * This config file is adapted from "config-suite-b.h" in mbedtls distribution.
 * The original file copyright/license is as follows:
 *   Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *   Licensed under the Apache License, Version 2.0
 * Refer to mbedtls for more details: https://tls.mbed.org
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H


// windows
#define MBEDTLS_PLATFORM_C

// custom memory allocation: mbedtls_platform_set_calloc_free
#define MBEDTLS_PLATFORM_MEMORY

#define MBEDTLS_VERSION_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_AESNI_C
#define MBEDTLS_FS_IO
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15

// note: GCM is better than CBC. enable CBC if you need VIA padlock support
//#define MBEDTLS_CIPHER_MODE_CBC
//#define MBEDTLS_PADLOCK_C

#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_HAVE_TIME_DATE

#define MBEDTLS_SSL_ENCRYPT_THEN_MAC
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

// note: sha1 seems to be required to validate some certificates
//   it is needed when loading/parsing ca certs file?
//     needed for signature algorithm (see mbedtls_oid_get_sig_alg in mbedtls_x509_get_sig_alg)?
#define MBEDTLS_SHA1_C

// the following is modified from "config-suite-b.h" in mbedtls distribution:

/* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME

/* mbed TLS feature support */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
// note: SECP384R1 is enabled to parse ca certs file - some certs may have this EC curve
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_SSL_PROTO_TLS1_2

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
//#define MBEDTLS_NET_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_SHA256_C
// note: sha-512 is enabled to parse ca certs file - some certs may have this md alg
#define MBEDTLS_SHA512_C
#define MBEDTLS_SSL_CLI_C
//#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C

/* For test certificates */
#define MBEDTLS_BASE64_C
#define MBEDTLS_CERTS_C
#define MBEDTLS_PEM_PARSE_C

/* Save RAM at the expense of ROM */
//#define MBEDTLS_AES_ROM_TABLES

/* Save RAM by adjusting to our exact needs */
//#define MBEDTLS_ECP_MAX_BITS   384
//#define MBEDTLS_MPI_MAX_SIZE    48 // 384 bits is 48 bytes

/* Save RAM at the expense of speed, see ecp.h */
//#define MBEDTLS_ECP_WINDOW_SIZE        2
//#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0

/* Significant speed benefit at the expense of some ROM */
#define MBEDTLS_ECP_NIST_OPTIM

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "mbedtls_platform_entropy_poll" source, but you may want to add other ones.
 * Minimum is 2 for the entropy test suite.
 */
//#define MBEDTLS_ENTROPY_MAX_SOURCES 2

/* Save ROM and a few bytes of RAM by specifying our own ciphersuite list */
/*#define MBEDTLS_SSL_CIPHERSUITES                        \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,    \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256*/

//#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

/*
 * Save RAM at the expense of interoperability: do this only if you control
 * both ends of the connection!  (See coments in "mbedtls/ssl.h".)
 * The minimum size here depends on the certificate chain used as well as the
 * typical size of records.
 */
//#define MBEDTLS_SSL_MAX_CONTENT_LEN             1024

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
