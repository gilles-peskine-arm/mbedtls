/*
 *  Common code for SSL test programs
 *
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_PROGRAMS_SSL_SSL_TEST_LIB_H
#define MBEDTLS_PROGRAMS_SSL_SSL_TEST_LIB_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free       free
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_calloc     calloc
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_SSL_TLS_C) && \
    defined(MBEDTLS_NET_C) && \
    defined(MBEDTLS_CTR_DRBG_C)
#define MBEDTLS_PROGRAMS_SSL__PREREQUISITES

#include <string.h>
#include <stdint.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"


/* Default values for some options that are intrinsically shared by
 * the client and the server. */
#define DFL_SERVER_ADDR         NULL
#define DFL_SERVER_PORT         "4433"
#define DFL_PSK                 ""
#define DFL_PSK_IDENTITY        "Client_identity"


void mbedtls_ssl_test_debug( void *ctx, int level,
                             const char *file, int line,
                             const char *str );

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
int mbedtls_ssl_test_recv( void *ctx, unsigned char *buf, size_t len );
int mbedtls_ssl_test_send( void *ctx, const unsigned char *buf, size_t len );

int mbedtls_ssl_test_force_ciphersuite( int force_ciphersuite,
                                        int transport,
                                        int min_version,
                                        int max_version,
                                        int *arc4 );

/*
 * Convert a hex string to bytes.
 * Return 0 on success, -1 on error.
 */
int mbedtls_ssl_test_unhexify( unsigned char *output,
                               const char *input,
                               size_t *olen );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/* Set the algorithm profile to allow SHA-1. Note that crt_profile must
 * remain valid as long as conf is in use. */
void mbedtls_ssl_test_conf_allow_sha1( mbedtls_ssl_config *conf,
                                       mbedtls_x509_crt_profile *crt_profile );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_ECP_C)
#define CURVE_LIST_SIZE 20
int mbedtls_ssl_test_parse_curves( char *p,
                                   mbedtls_ecp_group_id *curve_list );
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_ALPN)
#define ALPN_LIST_SIZE  10
int mbedtls_ssl_test_parse_alpn( char *p,
                                 const char *alpn_list[] );
#endif /* MBEDTLS_SSL_ALPN */

#endif /* MBEDTLS_PROGRAMS_SSL__PREREQUISITES */
#endif /* MBEDTLS_PROGRAMS_SSL_SSL_TEST_LIB_H */
