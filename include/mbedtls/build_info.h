/**
 * \file mbedtls/build_info.h
 *
 * \brief Build-time configuration info
 *
 *  Include this file if you need to depend on the
 *  configuration options defined in mbedtls_config.h or MBEDTLS_CONFIG_FILE
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_BUILD_INFO_H
#define MBEDTLS_BUILD_INFO_H

/*
 * This set of compile-time defines can be used to determine the version number
 * of the Mbed TLS library used. Run-time variables for the same can be found in
 * version.h
 */

/**
 * The version number x.y.z is split into three parts.
 * Major, Minor, Patchlevel
 */
#define MBEDTLS_VERSION_MAJOR  3
#define MBEDTLS_VERSION_MINOR  4
#define MBEDTLS_VERSION_PATCH  1

/**
 * The single version number has the following structure:
 *    MMNNPP00
 *    Major version | Minor version | Patch version
 */
#define MBEDTLS_VERSION_NUMBER         0x03040100
#define MBEDTLS_VERSION_STRING         "3.4.1"
#define MBEDTLS_VERSION_STRING_FULL    "mbed TLS 3.4.1"

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

/* Define `inline` on some non-C99-compliant compilers. */
#if (defined(__ARMCC_VERSION) || defined(_MSC_VER)) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/* X.509, TLS and non-PSA crypto configuration */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CONFIG_VERSION) && ( \
    MBEDTLS_CONFIG_VERSION < 0x03000000 || \
                             MBEDTLS_CONFIG_VERSION > MBEDTLS_VERSION_NUMBER)
#error "Invalid config version, defined value of MBEDTLS_CONFIG_VERSION is unsupported"
#endif

/* Target and application specific configurations
 *
 * Allow user to override any previous default.
 *
 */
#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

/* PSA crypto configuration */
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_CONFIG_FILE
#else
#include "psa/crypto_config.h"
#endif
#if defined(MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE
#endif
#endif /* defined(MBEDTLS_PSA_CRYPTO_CONFIG) */

/* Auto-enable MBEDTLS_CTR_DRBG_USE_128_BIT_KEY if
 * MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH and MBEDTLS_CTR_DRBG_C defined
 * to ensure a 128-bit key size in CTR_DRBG.
 */
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH) && defined(MBEDTLS_CTR_DRBG_C)
#define MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
#endif

/* Auto-enable MBEDTLS_MD_C if needed by a module that didn't require it
 * in a previous release, to ensure backwards compatibility.
 */
#if defined(MBEDTLS_PKCS5_C)
#define MBEDTLS_MD_C
#endif

/* PSA crypto specific configuration options
 * - If config_psa.h reads a configuration option in preprocessor directive,
 *   this symbol should be set before its inclusion. (e.g. MBEDTLS_MD_C)
 * - If config_psa.h writes a configuration option in conditional directive,
 *   this symbol should be consulted after its inclusion.
 *   (e.g. MBEDTLS_MD_LIGHT)
 */
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG) /* PSA_WANT_xxx influences MBEDTLS_xxx */ || \
    defined(MBEDTLS_PSA_CRYPTO_C) /* MBEDTLS_xxx influences PSA_WANT_xxx */
#include "mbedtls/config_psa.h"
#endif

#include "mbedtls/config_adjust_legacy_crypto.h"

/* The following blocks make it easier to disable all of TLS,
 * or of TLS 1.2 or 1.3 or DTLS, without having to manually disable all
 * key exchanges, options and extensions related to them. */

#if !defined(MBEDTLS_SSL_TLS_C)
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_PROTO_TLS1_2
#undef MBEDTLS_SSL_PROTO_DTLS
#endif

#if !defined(MBEDTLS_SSL_PROTO_DTLS)
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_SRTP
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_EARLY_DATA
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED))
#define MBEDTLS_SSL_TLS1_2_SOME_ECC
#endif

/* Make sure all configuration symbols are set before including check_config.h,
 * even the ones that are calculated programmatically. */
#include "mbedtls/check_config.h"

#endif /* MBEDTLS_BUILD_INFO_H */
