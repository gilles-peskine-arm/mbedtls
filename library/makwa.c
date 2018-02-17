/**
 * \file mbedtls_mawka.c
 *
 * \brief The Makwa password hashing algorithm.
 *
 * Reference: Thomas Pornin. The Makwa Password Hashing Function. Feb 22, 2014.
 */
/*  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MAKWA_C)

#include "mbedtls/bignum.h"
#include "mbedtls/makwa.h"
#include "mbedtls/md.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <string.h>

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/* constant-time buffer comparison */
static int mbedtls_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    const unsigned char *A = (const unsigned char *) a;
    const unsigned char *B = (const unsigned char *) b;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
        diff |= A[i] ^ B[i];

    return( diff );
}

/* 2.3 KDF step 3 or 5: set k <- HMAC_k(v || step || input) */
static int kdf_update_k( mbedtls_md_context_t *md_ctx,
                         size_t hash_length,
                         unsigned char *k,
                         const unsigned char *v,
                         unsigned char step,
                         const unsigned char *input0,
                         size_t input0_length,
                         const unsigned char *input1,
                         size_t input1_length,
                         const unsigned char *input2,
                         size_t input2_length )
{
    int ret;
    ret = mbedtls_md_hmac_starts( md_ctx, k, hash_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, v, hash_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, &step, 1 );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, input0, input0_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, input1, input1_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, input2, input2_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_finish( md_ctx, k );
    if( ret != 0 )
        return( ret );
    return( 0 );
}

/* KDF step 4 or 6: set v <- HMAC_k(v) */
static int kdf_update_v( mbedtls_md_context_t *md_ctx,
                         size_t hash_length,
                         const unsigned char *k,
                         unsigned char *v )
{
    int ret;
    ret = mbedtls_md_hmac_starts( md_ctx, k, hash_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, v, hash_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_finish( md_ctx, v );
    if( ret != 0 )
        return( ret );
    return( 0 );
}

/* 2.3 The KDF: H_{output_length}(input) */
static int makwa_kdf( const mbedtls_md_info_t *md_info,
                      const unsigned char *input0, size_t input0_length,
                      const unsigned char *input1, size_t input1_length,
                      const unsigned char *input2, size_t input2_length,
                      unsigned char *output, size_t output_length )
{
    unsigned char k[MBEDTLS_MD_MAX_SIZE];
    unsigned char v[MBEDTLS_MD_MAX_SIZE];
    int ret;
    size_t hash_length;
    mbedtls_md_context_t md_ctx;
    size_t offset;

    mbedtls_md_init( &md_ctx );
    ret = mbedtls_md_setup( &md_ctx, md_info, 1 );
    if( ret != 0 )
        return( ret );
    /* Let r = the size of a hash */
    hash_length = mbedtls_md_get_size( md_info );

    /* Check that the output generation won't cause an integer overflow */
    if( output_length >= (size_t) ( - hash_length ) )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    /* 1. Set V <- 0x01 [r times] */
    memset( v, 0x01, hash_length );

    /* 2. Set K <- 0x00 [r times] */
    memset( k, 0x00, hash_length );

    /* 3. Compute K <- HMAC_K(V || 0x00 || m) */
    ret = kdf_update_k( &md_ctx, hash_length, k, v, 0,
                        input0, input0_length,
                        input1, input1_length,
                        input2, input2_length );
    if( ret != 0 )
        goto exit;

    /* 4. Compute V <- HMAC_K(V) */
    ret = kdf_update_v( &md_ctx, hash_length, k, v );
    if( ret != 0 )
        goto exit;

    /* 5. Compute K <- HMAC_K(V || 0x01 || m) */
    ret = kdf_update_k( &md_ctx, hash_length, k, v, 1,
                        input0, input0_length,
                        input1, input1_length,
                        input2, input2_length );
    if( ret != 0 )
        goto exit;

    /* 6. Compute V <- HMAC_K(V) */
    ret = kdf_update_v( &md_ctx, hash_length, k, v );
    if( ret != 0 )
        goto exit;

    /* 7. Set T to an empty sequence */
    /* 8. While length(T) < output_length:
     *        Set V <- HMAC_K(V)
     *        Set T <- T || V
     *    output = output_length leftmost bytes of T */
    for( offset = 0; offset < output_length; offset += hash_length )
    {
        ret = kdf_update_v( &md_ctx, hash_length, k, v );
        if( ret != 0 )
            goto exit;
        memcpy( output + offset, v,
                ( offset + hash_length >= output_length ?
                  output_length - offset :
                  hash_length ) );
    }

exit:
    mbedtls_zeroize( k, sizeof( k ) );
    mbedtls_zeroize( v, sizeof( v ) );
    mbedtls_md_free( &md_ctx );
    if( ret != 0 )
        memset( output, 0, output_length );
    return( ret );
}

/* 2.6 Makwa core steps 1-3: from the (possibly pre-hashed) password input
 * and the salt, calculate the base x of the exponentiation. */
static int makwa_make_x( const mbedtls_md_info_t *md_info,
                         const unsigned char *input, unsigned char input_length,
                         const unsigned char *salt, size_t salt_length,
                         size_t k, mbedtls_mpi *x )
{
    int ret;
    unsigned char bytes[MBEDTLS_MPI_MAX_SIZE];

    /* Double-check that k is supported */
    if( k > MBEDTLS_MPI_MAX_SIZE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    /* 1. Padding: let S = H_{k-2-u}(salt || input || input_length) */
    ret = makwa_kdf( md_info,
                     salt, salt_length, input, input_length, &input_length, 1,
                     bytes + 1, k - 2 - input_length );
    if( ret != 0 )
        return( ret );

    /* 2. Let X = 0x00 || padding || input || input_length */
    bytes[0] = 0x00;
    memcpy( bytes + k - 1 - input_length, input, input_length );
    bytes[k - 1] = input_length;

    /* 3. Let x = integer decoded from X */
    ret = mbedtls_mpi_read_binary( x, bytes, k );

    mbedtls_zeroize( bytes, k );
    return( ret );
}

/* 2.6 Core Hashing */
static int makwa_core( const mbedtls_md_info_t *md_info,
                       const mbedtls_mpi *n, unsigned work_factor,
                       const unsigned char *input, size_t input_length,
                       const unsigned char *salt, size_t salt_length,
                       unsigned char *primary_output,
                       size_t primary_output_length )
{
    int ret;
    mbedtls_mpi x;
    mbedtls_mpi e;

    /* Let u = input_length */
    /* Let k = primary_output_length */
    /* Require k >= 160 */
    if( primary_output_length < 160 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    /* Require u <= 255 and u <= k -32 */
    if( input_length > 255 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    if( input_length > primary_output_length - 32 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
#if UINT_MAX > SIZE_MAX - 1
    if( work_factor > (size_t)( -2 ) )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
#endif

    mbedtls_mpi_init( &x );
    mbedtls_mpi_init( &e );

    /* Steps 1-3: build x from input and salt */
    ret = makwa_make_x( md_info, input, input_length, salt, salt_length,
                        primary_output_length, &x );
    if( ret != 0 )
        goto exit;

    /* 4. Compute y = x^{2^{w+1}} mod n */
    /* First let e = 2^{w+1} */
    ret = mbedtls_mpi_lset( &e, 1 );
    if( ret != 0 )
        goto exit;
    ret = mbedtls_mpi_shift_l( &e, work_factor + 1 );
    if( ret != 0 )
        goto exit;
    /* Calculate x^e and store the result back in x. */
    ret = mbedtls_mpi_exp_mod( &x, &x, &e, n, NULL );
    if( ret != 0 )
        goto exit;

    /* 5. Encode y into primary_output */
    ret = mbedtls_mpi_write_binary( &x, primary_output, primary_output_length );

exit:
    mbedtls_mpi_free( &x );
    mbedtls_mpi_free( &e );
    return( ret );
}

/* Makwa core + post-hashing if requested */
static int makwa_core_and_post( const mbedtls_md_info_t *md_info,
                                int post_hash,
                                const mbedtls_mpi *n, unsigned work_factor,
                                const unsigned char *input, size_t input_length,
                                const unsigned char *salt, size_t salt_length,
                                size_t primary_output_length,
                                unsigned char *output, size_t output_length )
{
    if( post_hash )
    {
        unsigned char primary_output[MBEDTLS_MPI_MAX_SIZE];
        int ret;
        /* 2.6 Core Hashing */
        ret = makwa_core( md_info, n, work_factor,
                          input, input_length, salt, salt_length,
                          primary_output, primary_output_length );
        if( ret == 0 )
        {
            /* 2.7 Post-Hashing */
            ret = makwa_kdf( md_info, primary_output, primary_output_length,
                             NULL, 0, NULL, 0,
                             output, output_length );
        }
        mbedtls_zeroize( primary_output, primary_output_length );
        return( ret );
    }
    else
    {
        /* 2.6 Core Hashing */
        return( makwa_core( md_info, n, work_factor,
                            input, input_length, salt, salt_length,
                            output, primary_output_length ) );
        /* 2.7 Post-Hashing is trivial */
    }

}

/* The full Makwa computation. */
int mbedtls_makwa_compute_raw( mbedtls_md_type_t md_alg,
                               const mbedtls_mpi *n, unsigned work_factor,
                               int pre_hash, int post_hash,
                               const unsigned char *input, size_t input_length,
                               const unsigned char *salt, size_t salt_length,
                               unsigned char *output, size_t output_length )
{
    int ret;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
    size_t primary_output_length = mbedtls_mpi_size( n );

    if( md_info == NULL )
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );
    if( ! post_hash && output_length != primary_output_length )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    if( pre_hash )
    {
        /* 2.5 Input Pre-Hashing: hashed_input <- H_{64}(input) */
        size_t hash_length = mbedtls_md_get_size( md_info );
        unsigned char hashed_input[64];
        ret = makwa_kdf( md_info, input, input_length,
                         NULL, 0, NULL, 0,
                         hashed_input, sizeof( hashed_input ) );
        if( ret != 0 )
            return( ret );
        /* 2.6 Core Hashing + 2.7 Post-Hashing */
        return( makwa_core_and_post( md_info, post_hash, n, work_factor,
                                     hashed_input, hash_length,
                                     salt, salt_length,
                                     primary_output_length,
                                     output, output_length ) );
    }
    else
    {
        /* 2.6 Core Hashing + 2.7 Post-Hashing */
        return( makwa_core_and_post( md_info, post_hash, n, work_factor,
                                     input, input_length,
                                     salt, salt_length,
                                     primary_output_length,
                                     output, output_length ) );
    }
}

/* The full Makwa computation, plus comparison against a reference hash. */
int mbedtls_makwa_verify_raw( mbedtls_md_type_t md_alg,
                              const mbedtls_mpi *n, unsigned work_factor,
                              int pre_hash, int post_hash,
                              const unsigned char *input, size_t input_length,
                              const unsigned char *salt, size_t salt_length,
                              const unsigned char *expected_output,
                              size_t output_length )
{
    int ret;
    unsigned char *actual_output = mbedtls_calloc( 1, output_length );
    if( actual_output == NULL )
        return( MBEDTLS_ERR_MD_ALLOC_FAILED );
    ret = mbedtls_makwa_compute_raw( md_alg, n, work_factor, pre_hash, post_hash,
                                     input, input_length, salt, salt_length,
                                     actual_output, output_length );
    if( ret == 0 )
    {
        if( mbedtls_safer_memcmp( expected_output, actual_output,
                                  output_length ) != 0 )
        {
            ret = MBEDTLS_ERR_MD_VERIFY_FAILED;
        }
    }
    mbedtls_zeroize( actual_output, output_length );
    mbedtls_free( actual_output );
    return( ret );
}

#endif /* MBEDTLS_MAKWA_C */
