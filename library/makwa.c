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

#include "mbedtls/base64.h"
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

#if defined(MBEDTLS_GENPRIME)
int mbedtls_makwa_generate_modulus_with_factors(
    size_t n_bits,
    mbedtls_mpi *n,
    mbedtls_mpi *p, mbedtls_mpi *q,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    int ret;

    if( n_bits % 2 != 0 )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    if( n == NULL || p == NULL || q == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    ret = mbedtls_mpi_gen_prime( p, n_bits / 2,
                                 MBEDTLS_MPI_GEN_PRIME_FLAG_3_MOD_4,
                                 f_rng, p_rng );
    if( ret != 0 )
        goto fail;
    ret = mbedtls_mpi_gen_prime( q, n_bits / 2,
                                 MBEDTLS_MPI_GEN_PRIME_FLAG_3_MOD_4,
                                 f_rng, p_rng );
    if( ret != 0 )
        goto fail;
    ret = mbedtls_mpi_mul_mpi( n, p, q );
    if( ret != 0 )
        goto fail;
    return( 0 );

fail:
    mbedtls_mpi_free( p );
    mbedtls_mpi_free( q );
    mbedtls_mpi_free( n );
    return( ret );
}

int mbedtls_makwa_generate_modulus(
    size_t n_bits,
    mbedtls_mpi *n,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    mbedtls_mpi tmp_p, tmp_q;
    int ret;
    mbedtls_mpi_init( &tmp_p );
    mbedtls_mpi_init( &tmp_q );
    ret = mbedtls_makwa_generate_modulus_with_factors( n_bits, n,
                                                       &tmp_p, &tmp_q,
                                                       f_rng, p_rng );
    mbedtls_mpi_free( &tmp_p );
    mbedtls_mpi_free( &tmp_q );
    return( ret );
}
#endif /* MBEDTLS_GENPRIME */

/* 2.3 KDF step 3 or 5: set k <- HMAC_k(v || step || input) */
static int kdf_update_k( mbedtls_md_context_t *md_ctx,
                         size_t hash_length,
                         unsigned char *k,
                         const unsigned char *v,
                         unsigned char step,
                         const unsigned char *const* inputs,
                         const size_t *input_lengths,
                         size_t nb_inputs )
{
    int ret;
    size_t i;
    ret = mbedtls_md_hmac_starts( md_ctx, k, hash_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, v, hash_length );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_md_hmac_update( md_ctx, &step, 1 );
    if( ret != 0 )
        return( ret );
    for( i = 0; i < nb_inputs; i++ )
    {
        ret = mbedtls_md_hmac_update( md_ctx, inputs[i], input_lengths[i] );
        if( ret != 0 )
            return( ret );
    }
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
int mbedtls_makwa_kdf( const mbedtls_md_info_t *md_info,
                       const unsigned char *const *inputs,
                       const size_t *input_lengths,
                       size_t nb_inputs,
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
                        inputs, input_lengths, nb_inputs );
    if( ret != 0 )
        goto exit;

    /* 4. Compute V <- HMAC_K(V) */
    ret = kdf_update_v( &md_ctx, hash_length, k, v );
    if( ret != 0 )
        goto exit;

    /* 5. Compute K <- HMAC_K(V || 0x01 || m) */
    ret = kdf_update_k( &md_ctx, hash_length, k, v, 1,
                        inputs, input_lengths, nb_inputs );
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
    const unsigned char *kdf_inputs[3] = { salt, input, &input_length };
    size_t kdf_input_lengths[3] = { salt_length, input_length, 1 };

    /* Double-check that k is supported */
    if( k > MBEDTLS_MPI_MAX_SIZE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    /* 1. Padding: let S = H_{k-2-u}(salt || input || input_length) */
    ret = mbedtls_makwa_kdf( md_info,
                             kdf_inputs, kdf_input_lengths, 3,
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
    mbedtls_mpi r;
    /* We'll need to calculate x^{2^{w+1}} mod n. The straightforward way is
     * to call mbedtls_mpi_exp_mod() with the exponent 2^{w+1}, but this
     * requires a lot of memory and may be over the MPI size limit. So
     * we'll repeated elevations to the 2^exp_steps power. Larger exp_steps
     * give better performance at the expense of memory. Use the size of n
     * as an indication of how much memory it's sensible to use. This gives
     * near-optimal performance because n must be at least 1273 bits and
     * that makes it large enough that going beyond only gives a tiny
     * performance benefit. */
    unsigned exp_step = mbedtls_mpi_size( n );

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
    mbedtls_mpi_init( &r );

    /* Steps 1-3: build x from input and salt */
    ret = makwa_make_x( md_info, input, input_length, salt, salt_length,
                        primary_output_length, &x );
    if( ret != 0 )
        goto exit;

    /* 4. Compute y = x^{2^{w+1}} mod n (stored back in x) */
    /* Let w = q * exp_step + r. Then
     *    x^{2^{w+1}} = ((...(x^{2^exp_step})...)^{2^exp_step})^{2^{r+1}}
     *                         `-----------------------------'
     *                                   q times
     */
    if( work_factor > exp_step )
    {
        ret = mbedtls_mpi_lset( &e, 1 );
        if( ret != 0 )
            goto exit;
        ret = mbedtls_mpi_shift_l( &e, exp_step );
        if( ret != 0 )
            goto exit;
        while( work_factor > exp_step )
        {
            ret = mbedtls_mpi_exp_mod( &x, &x, &e, n, &r );
            if( ret != 0 )
                goto exit;
            work_factor -= exp_step;
        }
    }
    ret = mbedtls_mpi_lset( &e, 1 );
    if( ret != 0 )
        goto exit;
    ret = mbedtls_mpi_shift_l( &e, work_factor + 1 );
    if( ret != 0 )
        goto exit;
    ret = mbedtls_mpi_exp_mod( &x, &x, &e, n, &r );
    if( ret != 0 )
        goto exit;

    /* 5. Encode y into primary_output */
    ret = mbedtls_mpi_write_binary( &x, primary_output, primary_output_length );

exit:
    mbedtls_mpi_free( &x );
    mbedtls_mpi_free( &e );
    mbedtls_mpi_free( &r );
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
            const unsigned char *po = primary_output;
            ret = mbedtls_makwa_kdf( md_info,
                                     &po, &primary_output_length, 1,
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
        unsigned char hashed_input[64];
        ret = mbedtls_makwa_kdf( md_info, &input, &input_length, 1,
                                 hashed_input, sizeof( hashed_input ) );
        if( ret != 0 )
            return( ret );
        /* 2.6 Core Hashing + 2.7 Post-Hashing */
        return( makwa_core_and_post( md_info, post_hash, n, work_factor,
                                     hashed_input, sizeof( hashed_input ),
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

#if defined(MBEDTLS_BASE64_C)

/* B64 is Base64 without newlines and without trailing '='. (Ref: A.4.1) */
static size_t b64_length( size_t bytes )
{
    return( bytes / 3 * 4 + ( bytes % 3 == 0 ? 0 : bytes % 3 + 1 ) );
}
#define B64_MAX_INPUT_LENGTH ( SIZE_MAX / 4 * 3 - 2 )

/* Length of the Makwa string format output. Does not include a trailing
 * null byte. (Ref: A.4.2) */
static size_t makwa_b64_length( size_t salt_length, size_t output_length )
{
    size_t length = b64_length( 8 ) + 1 + 4 + 1 + 1;
    if( salt_length >= B64_MAX_INPUT_LENGTH )
        return( SIZE_MAX );
    if( output_length >= B64_MAX_INPUT_LENGTH )
        return( SIZE_MAX );
    if( length + b64_length( salt_length ) < length )
        return( SIZE_MAX );
    length += b64_length( salt_length );
    if( length + b64_length( output_length ) < length )
        return( SIZE_MAX );
    length += b64_length( output_length );
    return( length );
}

/* Base64 encoding without trailing '=' for padding.
 * Write a trailing null byte, but this byte is not included in *olen. */
static int b64_encode( char *dst, size_t dlen, size_t *olen,
                       const unsigned char *src, size_t slen )
{
    size_t swhole_len = slen - slen % 3;
    int ret;
    unsigned char *udst = (unsigned char *) dst;

    /* First encode whole 3-byte blocks so that the output does not
     * include padding, because there might not be enough room for the
     * padding. */
    ret = mbedtls_base64_encode( udst, dlen, olen, src, swhole_len );
    if( ret != 0 )
        return( ret );

    /* Now encode the remaining 0-2 bytes. */
    if( swhole_len != slen )
    {
        unsigned char trail[5];
        size_t trail_len;
        ret = mbedtls_base64_encode( trail, sizeof( trail ), &trail_len,
                                     src + swhole_len, slen - swhole_len );
        if( ret == 0 )
        {
            unsigned i;
            for( i = 0; trail[i] != '='; i++ )
                udst[( *olen )++] = trail[i];
            udst[*olen] = 0;
        }
        mbedtls_zeroize( trail, sizeof( trail ) );
    }

    return( ret );
}

/* Decode B64 data from cursor up to the first occurrence of the terminator
 * character. Allocate a buffer for the result and return the buffer through
 * output and output_length. */
static int b64_decode( const char **cursor, char terminator,
                       unsigned char **buffer, size_t *output_length )
{
    char *end = strchr( *cursor, terminator );
    size_t input_length;
    size_t decoded_length;
    int ret;

    if( end == NULL )
        return( MBEDTLS_ERR_MD_VERIFY_FAILED );
    input_length = end - *cursor;

    /* Allocate the output buffer. */
    *output_length = input_length / 4 * 3;
    switch( input_length % 4 )
    {
        case 0: break;
        case 1: return( MBEDTLS_ERR_MD_VERIFY_FAILED );
        case 2: *output_length += 1; break;
        case 3: *output_length += 2; break;
    }
    *buffer = mbedtls_calloc( 1, *output_length );
    if( *buffer == NULL )
        return( MBEDTLS_ERR_MD_ALLOC_FAILED );

    /* Decode all but the last partial block (if any). */
    ret = mbedtls_base64_decode( *buffer, *output_length, &decoded_length,
                                 (unsigned char *) ( *cursor ),
                                 input_length - input_length % 4 );
    if( ret != 0 )
        goto fail;

    if( input_length % 4 != 0 )
    {
        /* Decode the last partial block. */
        unsigned char trail[4] = "====";
        memcpy( trail, *cursor + input_length - input_length % 4,
                input_length % 4 );
        ret = mbedtls_base64_decode( *buffer + decoded_length,
                                     *output_length - decoded_length,
                                     &decoded_length,
                                     trail, sizeof( trail ) );
        mbedtls_zeroize( trail, input_length % 4 );
        if( ret != 0 )
            goto fail;
    }

    *cursor = end + 1;
    return( 0 );

fail:
    mbedtls_zeroize( *buffer, *output_length );
    mbedtls_free( *buffer );
    *buffer = NULL;
    if( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER )
        ret = MBEDTLS_ERR_MD_VERIFY_FAILED;
    return( ret );
}

/* Calculate B64(H_8(N)), the Base64 encoding of the checksum of the
 * modulus. (Ref: A.4.2) */
static int modulus_checksum( mbedtls_md_type_t md_alg, const mbedtls_mpi *n,
                             char *dst, size_t dsize )
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
    size_t n_byte_size = mbedtls_mpi_size( n );
    unsigned char *n_bytes;
    size_t base64_length;
    int ret;

    if( md_info == NULL )
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );
    if( n_byte_size < 8 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    n_bytes = mbedtls_calloc( 1, n_byte_size );
    if( n_bytes == NULL )
        return( MBEDTLS_ERR_MD_ALLOC_FAILED );

    ret = mbedtls_mpi_write_binary( n, n_bytes, n_byte_size );
    if( ret != 0 )
        goto exit;
    ret = mbedtls_makwa_kdf( md_info,
                             (const unsigned char **) &n_bytes, &n_byte_size, 1,
                             n_bytes, 8 );
    if( ret != 0 )
        goto exit;

    ret = b64_encode( dst, dsize, &base64_length, n_bytes, 8 );
    if( ret == 0 )
        ret = base64_length;

exit:
    if( n_bytes != NULL )
        mbedtls_zeroize( n_bytes, n_byte_size );
    mbedtls_free( n_bytes );
    return( ret );
}

/* The full Makwa computation, with the result encoded as a printable
 * string as defined in Appendix A.4. */
int mbedtls_makwa_compute_base64( mbedtls_md_type_t md_alg,
                                  const mbedtls_mpi *n, unsigned work_factor,
                                  int pre_hash, int post_hash,
                                  const unsigned char *input,
                                  size_t input_length,
                                  const unsigned char *salt,
                                  size_t salt_length,
                                  size_t raw_output_length,
                                  char *output,
                                  size_t output_buffer_size )
{
    int ret;
    size_t base64_output_length =
        makwa_b64_length( salt_length, raw_output_length );
    unsigned char *raw_output = NULL;
    char *cursor = output;
    char *end = output + output_buffer_size;
    size_t chunk_length;
    unsigned zeta;
    unsigned delta;

    /* Enforce the minimum output length required by the specification. */
    if( raw_output_length < 10 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    /* Check that there is enough room for the output plus a trailing
     * null byte. */
    if( base64_output_length == SIZE_MAX )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    if( output_buffer_size < base64_output_length + 1 )
        return( MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL );

    /* Decompose the work factor into zeta * 2^delta */
    delta = 0;
    for( zeta = work_factor; zeta > 3; zeta >>= 1 )
        ++delta;
    if( zeta != 2 && zeta != 3 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    if( delta > 99 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    /* Write B64(H_8(N)) || "_" */
    ret = modulus_checksum( md_alg, n, cursor, end - cursor );
    if( ret < 0 )
        goto exit;
    cursor += ret;
    *( cursor++ ) = '_';

    /* Write F || "_" */
    *( cursor++ ) = ( pre_hash ? post_hash ? 'b' : 'r' :
                                 post_hash ? 's' : 'n' );
    *( cursor++ ) = '0' + zeta;
    *( cursor++ ) = '0' + ( delta / 10 );
    *( cursor++ ) = '0' + ( delta % 10 );
    *( cursor++ ) = '_';

    /* Write B64(salt) || "_" */
    ret = b64_encode( cursor, end - cursor, &chunk_length,
                      salt, salt_length );
    if( ret != 0 )
        goto exit;
    cursor += chunk_length;
    *( cursor++ ) = '_';

    /* Write B64(raw_output) */
    raw_output = mbedtls_calloc( 1, raw_output_length );
    if( raw_output == NULL )
    {
        ret = MBEDTLS_ERR_MD_ALLOC_FAILED;
        goto exit;
    }
    ret = mbedtls_makwa_compute_raw( md_alg, n, work_factor,
                                     pre_hash, post_hash,
                                     input, input_length, salt, salt_length,
                                     raw_output, raw_output_length );
    if( ret != 0 )
        goto exit;
    ret = b64_encode( cursor, end - cursor, &chunk_length,
                      raw_output, raw_output_length / 3 * 3 );
    if( ret != 0 )
        goto exit;
    cursor += chunk_length;

exit:
    if( raw_output != NULL )
        mbedtls_zeroize( raw_output, raw_output_length );
    mbedtls_free( raw_output );
    if( ret != 0 )
        memset( output, 0, output_buffer_size );
    return( ret );
}

/* Parse the work factor from the string format (Ref: A.4.2). The work
 * factor z*2^dd is encoded as "zdd" with "z" and "dd" encoded in decimal
 * as 1 and 2 digits respectively. */
static int parse_work_factor( const char *cursor, unsigned *work_factor )
{
    unsigned zeta, delta;
    unsigned i;

    /* Parse a 1-digit decimal number and a 2-digit decimal number. */
    for( i = 0; i <= 2; i++ )
    {
        if( cursor[i] < '0' || cursor[i] > '9' )
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }
    zeta = cursor[0] - '0';
    delta = ( cursor[1] - '0' ) * 10 + ( cursor[2] - '0' );

    /* Check that zeta is permitted. */
    if( zeta != 2 && zeta != 3)
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    /* Check that delta is supported, i.e. that there won't be any overflow
     * when calculating work_factor. */
    if( delta > CHAR_BIT * sizeof( *work_factor ) - 2 )
    {
        /* A work factor that doesn't fit in unsigned int is
         * absurdly large, but permitted by the specification. */
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );
    }
    *work_factor = zeta << delta;
    return( 0 );
}

/* Verify a password against a reference output from the Makwa algorithm
 * formatted as a printable string as defined in Appendix A.4. */
int mbedtls_makwa_verify_base64( mbedtls_md_type_t md_alg,
                                 const mbedtls_mpi *n,
                                 const unsigned char *input,
                                 size_t input_length,
                                 const char *expected_output )
{
    char encoded_n[12];
    unsigned work_factor;
    int pre_hash, post_hash;
    unsigned char *salt = NULL;
    size_t salt_length;
    unsigned char *raw_output = NULL;
    size_t raw_output_length;
    const char *cursor = expected_output;
    int ret;

    /* Parse and check B64(H_8(N)) || "_" */
    ret = modulus_checksum( md_alg, n, encoded_n, sizeof( encoded_n ) );
    if( ret < 0 )
        goto exit;
    if( cursor[ret] != '_' )
    {
        ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
        goto exit;
    }
    if( strncmp( cursor, encoded_n, ret ) != 0 )
    {
        ret = MBEDTLS_ERR_MD_VERIFY_FAILED;
        goto exit;
    }
    cursor += ret + 1;

    /* Parse and check F || "_" */
    switch( *cursor )
    {
        case 'n': pre_hash = 0; post_hash = 0; break;
        case 'r': pre_hash = 1; post_hash = 0; break;
        case 's': pre_hash = 0; post_hash = 1; break;
        case 'b': pre_hash = 1; post_hash = 1; break;
        default:
            ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            goto exit;
    }
    ++cursor;
    ret = parse_work_factor( cursor, &work_factor );
    if( ret != 0 )
        goto exit;
    cursor += 3;
    if( *cursor != '_' )
    {
        ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
        goto exit;
    }
    ++cursor;

    /* Parse B64(salt) || "_" */
    ret = b64_decode( &cursor, '_', &salt, &salt_length );
    if( ret != 0 )
        goto exit;

    /* Parse B64(output) */
    ret = b64_decode( &cursor, 0, &raw_output, &raw_output_length );
    if( ret != 0 )
        goto exit;
    /* 10 is the minimum hash size specified for the Base64 format. */
    if( raw_output_length < 10 )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    ret = mbedtls_makwa_verify_raw( md_alg, n, work_factor,
                                    pre_hash, post_hash,
                                    input, input_length,
                                    salt, salt_length,
                                    raw_output, raw_output_length );

exit:
    if( salt != NULL )
        mbedtls_zeroize( salt, salt_length );
    mbedtls_free( salt );
    if( raw_output != NULL )
        mbedtls_zeroize( raw_output, raw_output_length );
    mbedtls_free( raw_output );
    return( ret );
}

#endif /* MBEDTLS_BASE64_C */

#endif /* MBEDTLS_MAKWA_C */
