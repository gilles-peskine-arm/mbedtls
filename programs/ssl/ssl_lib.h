/*
 *  Shared code for SSL clients and servers
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_PROGRAMS_SSL_LIB_H
#define MBEDTLS_PROGRAMS_SSL_LIB_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"


#if defined(MBEDTLS_SSL_ASYNC_PRIVATE_C) && defined(MBEDTLS_X509_CRT_PARSE_C)
typedef struct
{
    mbedtls_x509_crt *cert;
    mbedtls_pk_context *pk;
    unsigned delay;
} ssl_async_key_slot_t;

typedef enum {
    SSL_ASYNC_INJECT_ERROR_NONE = 0,
    SSL_ASYNC_INJECT_ERROR_FALLBACK,
    SSL_ASYNC_INJECT_ERROR_START,
    SSL_ASYNC_INJECT_ERROR_CANCEL,
    SSL_ASYNC_INJECT_ERROR_RESUME,
    SSL_ASYNC_INJECT_ERROR_PK
#define SSL_ASYNC_INJECT_ERROR_MAX SSL_ASYNC_INJECT_ERROR_PK
} ssl_async_inject_error_t;

typedef struct
{
    ssl_async_key_slot_t slots[2];
    size_t slots_used;
    ssl_async_inject_error_t inject_error;
    int (*f_rng)(void *, unsigned char *, size_t);
    void *p_rng;
} ssl_async_key_context_t;

#define SSL_ASYNC_INPUT_MAX_SIZE 512
typedef struct
{
    size_t slot;
    mbedtls_md_type_t md_alg;
    unsigned char input[SSL_ASYNC_INPUT_MAX_SIZE];
    size_t input_len;
    unsigned delay;
} ssl_async_operation_context_t;

void ssl_async_set_key( ssl_async_key_context_t *ctx,
                        mbedtls_x509_crt *cert,
                        mbedtls_pk_context *pk,
                        unsigned delay );

int ssl_async_sign( void *connection_ctx_arg,
                    void **p_operation_ctx,
                    mbedtls_x509_crt *cert,
                    mbedtls_md_type_t md_alg,
                    const unsigned char *hash,
                    size_t hash_len );

int ssl_async_decrypt( void *connection_ctx_arg,
                       void **p_operation_ctx,
                       mbedtls_x509_crt *cert,
                       const unsigned char *input,
                       size_t input_len );

int ssl_async_resume( void *connection_ctx_arg,
                      void *operation_ctx_arg,
                      unsigned char *output,
                      size_t *output_len,
                      size_t output_size );

void ssl_async_cancel( void *connection_ctx_arg,
                       void *operation_ctx_arg );
#endif /* defined(MBEDTLS_SSL_ASYNC_PRIVATE_C) && defined(MBEDTLS_X509_CRT_PARSE_C) */


#endif /* MBEDTLS_PROGRAMS_SSL_LIB_H */
