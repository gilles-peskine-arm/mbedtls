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

#include "ssl_lib.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#if defined(MBEDTLS_SSL_ASYNC_PRIVATE_C) && defined(MBEDTLS_X509_CRT_PARSE_C)
void ssl_async_set_key( ssl_async_key_context_t *ctx,
                        mbedtls_x509_crt *cert,
                        mbedtls_pk_context *pk,
                        unsigned delay )
{
    ctx->slots[ctx->slots_used].cert = cert;
    ctx->slots[ctx->slots_used].pk = pk;
    ctx->slots[ctx->slots_used].delay = delay;
    ++ctx->slots_used;
}

static int ssl_async_start( void *connection_ctx_arg,
                            void **p_operation_ctx,
                            mbedtls_x509_crt *cert,
                            const char *op_name,
                            mbedtls_md_type_t md_alg,
                            const unsigned char *input,
                            size_t input_len )
{
    ssl_async_key_context_t *key_ctx = connection_ctx_arg;
    size_t slot;
    ssl_async_operation_context_t *ctx = NULL;
    {
        char dn[100];
        mbedtls_x509_dn_gets( dn, sizeof( dn ), &cert->subject );
        mbedtls_printf( "Async %s callback: looking for DN=%s\n", op_name, dn );
    }
    for( slot = 0; slot < key_ctx->slots_used; slot++ )
    {
        if( key_ctx->slots[slot].cert == cert )
            break;
    }
    if( slot == key_ctx->slots_used )
    {
        mbedtls_printf( "Async %s callback: no key matches this certificate.\n",
                        op_name );
        return( MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH );
    }
    if( key_ctx->inject_error == SSL_ASYNC_INJECT_ERROR_FALLBACK )
    {
        mbedtls_printf( "Async %s callback: injected fallback.\n",
                        op_name );
        return( MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH );
    }
    mbedtls_printf( "Async %s callback: using key slot %zd, delay=%u.\n",
                    op_name, slot, key_ctx->slots[slot].delay );
    if( key_ctx->inject_error == SSL_ASYNC_INJECT_ERROR_START )
    {
        mbedtls_printf( "Async %s callback: injected error\n", op_name );
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
    }
    if( input_len > SSL_ASYNC_INPUT_MAX_SIZE )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    ctx = mbedtls_calloc( 1, sizeof( *ctx ) );
    if( ctx == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    ctx->slot = slot;
    ctx->md_alg = md_alg;
    memcpy( ctx->input, input, input_len );
    ctx->input_len = input_len;
    ctx->delay = key_ctx->slots[slot].delay;
    *p_operation_ctx = ctx;
    if( ctx->delay == 0 )
        return( 0 );
    else
        return( MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS );
}

int ssl_async_sign( void *connection_ctx_arg,
                    void **p_operation_ctx,
                    mbedtls_x509_crt *cert,
                    mbedtls_md_type_t md_alg,
                    const unsigned char *hash,
                    size_t hash_len )
{
    return( ssl_async_start( connection_ctx_arg, p_operation_ctx, cert,
                             "sign", md_alg,
                             hash, hash_len ) );
}

int ssl_async_decrypt( void *connection_ctx_arg,
                       void **p_operation_ctx,
                       mbedtls_x509_crt *cert,
                       const unsigned char *input,
                       size_t input_len )
{
    return( ssl_async_start( connection_ctx_arg, p_operation_ctx, cert,
                             "decrypt", MBEDTLS_MD_NONE,
                             input, input_len ) );
}

int ssl_async_resume( void *connection_ctx_arg,
                      void *operation_ctx_arg,
                      unsigned char *output,
                      size_t *output_len,
                      size_t output_size )
{
    ssl_async_operation_context_t *ctx = operation_ctx_arg;
    ssl_async_key_context_t *connection_ctx = connection_ctx_arg;
    ssl_async_key_slot_t *key_slot = &connection_ctx->slots[ctx->slot];
    int ret;
    const char *op_name;
    if( connection_ctx->inject_error == SSL_ASYNC_INJECT_ERROR_RESUME )
    {
        mbedtls_printf( "Async resume callback: injected error\n" );
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
    }
    if( ctx->delay > 0 )
    {
        --ctx->delay;
        mbedtls_printf( "Async resume (slot %zd): call %u more times.\n",
                        ctx->slot, ctx->delay );
        return( MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS );
    }
    if( ctx->md_alg == MBEDTLS_MD_NONE )
    {
        op_name = "decrypt";
        ret = mbedtls_pk_decrypt( key_slot->pk,
                                  ctx->input, ctx->input_len,
                                  output, output_len, output_size,
                                  connection_ctx->f_rng, connection_ctx->p_rng );
    }
    else
    {
        op_name = "sign";
        ret = mbedtls_pk_sign( key_slot->pk,
                               ctx->md_alg,
                               ctx->input, ctx->input_len,
                               output, output_len,
                               connection_ctx->f_rng, connection_ctx->p_rng );
    }
    if( connection_ctx->inject_error == SSL_ASYNC_INJECT_ERROR_PK )
    {
        mbedtls_printf( "Async resume callback: %s done but injected error\n",
                        op_name );
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
    }
    mbedtls_printf( "Async resume (slot %zd): %s done, status=%d.\n",
                    ctx->slot, op_name, ret );
    mbedtls_free( ctx );
    return( ret );
}

void ssl_async_cancel( void *connection_ctx_arg,
                       void *operation_ctx_arg )
{
    ssl_async_operation_context_t *ctx = operation_ctx_arg;
    (void) connection_ctx_arg;
    mbedtls_printf( "Async cancel callback.\n" );
    mbedtls_free( ctx );
}
#endif /* defined(MBEDTLS_SSL_ASYNC_PRIVATE_C) && defined(MBEDTLS_X509_CRT_PARSE_C) */

