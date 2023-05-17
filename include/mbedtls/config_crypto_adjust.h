/**
 * \file mbedtls/config_crypto_adjust.h
 * \brief Adjust the legacy crypto configuration (various MBEDTLS_xxx symbols)
 *        to automatically enable dependencies or simplify some
 *        configuration checks.
 *
 * Do not include this header directly! It is automatically included
 * by public headers as needed.
 *
 * This header never automatically enables cryptographic mechanisms as such:
 * in the legacy crypto API, if A requires B then a user who wants A and
 * doesn't care about B must manually enable both A and B. In this header:
 *
 * - We enable automatic dependencies on sub-features such as xxx_LIGHT
 *   added after Mbed TLS 3.0 and mostly intended for internal purposes.
 * - We enable some internal dependencies on high-level interface modules
 *   such as MD, cipher and PK.
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

#ifndef MBEDTLS_CONFIG_CRYPTO_ADJUST_H
#define MBEDTLS_CONFIG_CRYPTO_ADJUST_H

/* Auto-enable MBEDTLS_MD_C if needed by a module that didn't require it
 * in a previous release, to ensure backwards compatibility.
 */
#if defined(MBEDTLS_PKCS5_C)
#define MBEDTLS_MD_C
#endif

/* Auto-enable MBEDTLS_MD_LIGHT based on MBEDTLS_MD_C.
 * This allows checking for MD_LIGHT rather than MD_LIGHT || MD_C.
 */
#if defined(MBEDTLS_MD_C)
#define MBEDTLS_MD_LIGHT
#endif

/* Auto-enable MBEDTLS_MD_LIGHT if needed by a module that didn't require it
 * in a previous release, to ensure backwards compatibility.
 */
#if defined(MBEDTLS_ECJPAKE_C) || \
    defined(MBEDTLS_PEM_PARSE_C) || \
    defined(MBEDTLS_ENTROPY_C) || \
    defined(MBEDTLS_PKCS12_C) || \
    defined(MBEDTLS_RSA_C)
#define MBEDTLS_MD_LIGHT
#endif

/* MBEDTLS_ECP_C now consists of MBEDTLS_ECP_LIGHT plus functions for curve
 * arithmetic. As a consequence if MBEDTLS_ECP_C is required for some reason,
 * then MBEDTLS_ECP_LIGHT should be enabled as well. */
#if defined(MBEDTLS_ECP_C)
#define MBEDTLS_ECP_LIGHT
#endif

/* The PK wrappers need pk_write functions to format RSA key objects
 * when they are dispatching to the PSA API. This happens under USE_PSA_CRYPTO,
 * and also even without USE_PSA_CRYPTO for mbedtls_pk_sign_ext(). */
#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_RSA_C)
#define MBEDTLS_PK_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_PARSE_C
#endif

#endif /* MBEDTLS_CONFIG_CRYPTO_ADJUST_H */
