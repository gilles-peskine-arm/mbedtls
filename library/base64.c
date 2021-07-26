/*
 *  RFC 1521 base64 encoding/decoding
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
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
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  **********
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_BASE64_C)

#include "mbedtls/base64.h"

#include <stdint.h>

#if defined(MBEDTLS_SELF_TEST)
#include <string.h>
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

/* Given a value in the range 0..63, return the corresponding base64 digit.
 * The implementation assumes that letters are consecutive (e.g. ASCII
 * but not EBCDIC).
 */
static unsigned char base64_enc_char( unsigned char value )
{
    if( value < 26 )
        return( 'A' + value );
    else if( value < 52 )
        return( 'a' + value - 26 );
    else if( value < 62 )
        return( '0' + value - 52 );
    else if( value == 62 )
        return( '+' );
    else
        return( '/' );
}

#define BASE64_SIZE_T_MAX   ( (size_t) -1 ) /* SIZE_T_MAX is not standard */

/*
 * Encode a buffer into base64 format
 */
int mbedtls_base64_encode( unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen )
{
    size_t i, n;
    int C1, C2, C3;
    unsigned char *p;

    if( slen == 0 )
    {
        *olen = 0;
        return( 0 );
    }

    n = slen / 3 + ( slen % 3 != 0 );

    if( n > ( BASE64_SIZE_T_MAX - 1 ) / 4 )
    {
        *olen = BASE64_SIZE_T_MAX;
        return( MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL );
    }

    n *= 4;

    if( ( dlen < n + 1 ) || ( NULL == dst ) )
    {
        *olen = n + 1;
        return( MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL );
    }

    n = ( slen / 3 ) * 3;

    for( i = 0, p = dst; i < n; i += 3 )
    {
        C1 = *src++;
        C2 = *src++;
        C3 = *src++;

        *p++ = base64_enc_char( (C1 >> 2) & 0x3F );
        *p++ = base64_enc_char( (((C1 &  3) << 4) + (C2 >> 4)) & 0x3F );
        *p++ = base64_enc_char( (((C2 & 15) << 2) + (C3 >> 6)) & 0x3F );
        *p++ = base64_enc_char( C3 & 0x3F );
    }

    if( i < slen )
    {
        C1 = *src++;
        C2 = ( ( i + 1 ) < slen ) ? *src++ : 0;

        *p++ = base64_enc_char( (C1 >> 2) & 0x3F );
        *p++ = base64_enc_char( (((C1 & 3) << 4) + (C2 >> 4)) & 0x3F );

        if( ( i + 1 ) < slen )
            *p++ = base64_enc_char( ((C2 & 15) << 2) & 0x3F );
        else *p++ = '=';

        *p++ = '=';
    }

    *olen = p - dst;
    *p = 0;

    return( 0 );
}

typedef enum
{
    INVALID = 0,
    CR,
    LF,
    SPACE,
    EQUAL,
    BODY,
} base64_character_type;

/* Return 0xff if low <= c <= high, 0 otherwise.
 *
 * Constant flow with respect to c.
 */
static uint8_t mask_of_range( uint8_t low, uint8_t high, uint8_t c )
{
    unsigned low_mask = ( c - low ) >> 8;
    unsigned high_mask = ( c - high - 1 ) >> 8;
    return( ~low_mask & high_mask & 0xff );
}

/* Given any byte value, return its syntactic category in Base64 source.
 * The implementation assumes that the input is in a character set where
 * letters, digits and '+' and '/' are encoded as the same value as in ASCII.
 */
static base64_character_type base64_get_type( unsigned char c )
{
    base64_character_type type = INVALID;

    /* Halve the input space */
    if( c & 0x80 )
        return( INVALID );

    /* Body characters (constant-flow) */
    type |= mask_of_range( 'A', 'Z', c ) & BODY;
    type |= mask_of_range( 'a', 'z', c ) & BODY;
    type |= mask_of_range( '0', '9', c ) & BODY;
    type |= mask_of_range( '+', '+', c ) & BODY;
    type |= mask_of_range( '/', '/', c ) & BODY;

    /* Non-body characters. Doesn't have to be constant-flow, but using a
     * switch-case here causes GCC 9.3.0 -O2 on x86_64 to emit code that
     * checks the switch-case values before calling mask_of_range, which
     * leaks information about c <= '=', and doesn't improve performance
     * measurably. */
    type |= mask_of_range( '=', '=', c ) & EQUAL;
    type |= mask_of_range( '\r', '\r', c ) & CR;
    type |= mask_of_range( '\n', '\n', c ) & LF;
    type |= mask_of_range( ' ', ' ', c ) & SPACE;

    return( type );
}

/* Given a Base64 digit, return its value.
 * The result is unspecified if c is not a Base64 digit ('A'..'Z', 'a'..'z',
 * '0'..'9', '+' or '/').
 *
 * The implementation assumes that letters are consecutive (e.g. ASCII
 * but not EBCDIC).
 *
 * The implementation is constant-flow (no branch or memory access depending
 * on the value of c) unless the compiler inlines and optimizes a specific
 * access.
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static uint8_t base64_dec_char( uint8_t c )
{
    uint8_t value = 0;
    value |= mask_of_range( 'A', 'Z', c ) & ( c - 'A' + 0 );
    value |= mask_of_range( 'a', 'z', c ) & ( c - 'a' + 26 );
    value |= mask_of_range( '0', '9', c ) & ( c - '0' + 52 );
    value |= mask_of_range( '+', '+', c ) & ( c - '+' + 62 );
    value |= mask_of_range( '/', '/', c ) & ( c - '/' + 63 );
    return( value );
}

/*
 * Decode a base64-formatted buffer
 */
int mbedtls_base64_decode( unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen )
{
    size_t i, n;
    uint32_t j, x;
    unsigned char *p;

    /* First pass: check for validity and get output length */
    for( i = n = j = 0; i < slen; i++ )
    {
        base64_character_type type = base64_get_type( src[i] );

        /* Skip spaces before checking for EOL */
        x = 0;
        while( i < slen && type == SPACE )
        {
            ++i;
            ++x;
            type = base64_get_type( src[i] );
        }

        /* Spaces at end of buffer are OK */
        if( i == slen )
            break;

        if( type == CR )
        {
            if( slen - i >= 2 && base64_get_type( src[i + 1] ) == LF )
                continue;
            else
                return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );
        }

        if( type == LF )
            continue;

        /* Space inside a line is an error */
        if( x != 0 )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        if( type == EQUAL && ++j > 2 )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        if( type == INVALID )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        if( type == BODY && j != 0 )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        n++;
    }

    if( n == 0 )
    {
        *olen = 0;
        return( 0 );
    }

    /* The following expression is to calculate the following formula without
     * risk of integer overflow in n:
     *     n = ( ( n * 6 ) + 7 ) >> 3;
     */
    n = ( 6 * ( n >> 3 ) ) + ( ( 6 * ( n & 0x7 ) + 7 ) >> 3 );
    n -= j;

    if( dst == NULL || dlen < n )
    {
        *olen = n;
        return( MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL );
    }

   for( j = 3, n = x = 0, p = dst; i > 0; i--, src++ )
   {
        base64_character_type type = base64_get_type( *src );
        switch( type )
        {
            case BODY:
                x = ( x << 6 ) | base64_dec_char( *src );
                break;
            case EQUAL:
                j -= 1;
                x <<= 6;
                break;
            default:
                continue;
        }

        if( ++n == 4 )
        {
            n = 0;
            if( j > 0 ) *p++ = (unsigned char)( x >> 16 );
            if( j > 1 ) *p++ = (unsigned char)( x >>  8 );
            if( j > 2 ) *p++ = (unsigned char)( x       );
        }
    }

    *olen = p - dst;

    return( 0 );
}

#if defined(MBEDTLS_SELF_TEST)

static const unsigned char base64_test_dec[64] =
{
    0x24, 0x48, 0x6E, 0x56, 0x87, 0x62, 0x5A, 0xBD,
    0xBF, 0x17, 0xD9, 0xA2, 0xC4, 0x17, 0x1A, 0x01,
    0x94, 0xED, 0x8F, 0x1E, 0x11, 0xB3, 0xD7, 0x09,
    0x0C, 0xB6, 0xE9, 0x10, 0x6F, 0x22, 0xEE, 0x13,
    0xCA, 0xB3, 0x07, 0x05, 0x76, 0xC9, 0xFA, 0x31,
    0x6C, 0x08, 0x34, 0xFF, 0x8D, 0xC2, 0x6C, 0x38,
    0x00, 0x43, 0xE9, 0x54, 0x97, 0xAF, 0x50, 0x4B,
    0xD1, 0x41, 0xBA, 0x95, 0x31, 0x5A, 0x0B, 0x97
};

static const unsigned char base64_test_enc[] =
    "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPK"
    "swcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==";

/*
 * Checkup routine
 */
int mbedtls_base64_self_test( int verbose )
{
    size_t len;
    const unsigned char *src;
    unsigned char buffer[128];

    if( verbose != 0 )
        mbedtls_printf( "  Base64 encoding test: " );

    src = base64_test_dec;

    if( mbedtls_base64_encode( buffer, sizeof( buffer ), &len, src, 64 ) != 0 ||
         memcmp( base64_test_enc, buffer, 88 ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  Base64 decoding test: " );

    src = base64_test_enc;

    if( mbedtls_base64_decode( buffer, sizeof( buffer ), &len, src, 88 ) != 0 ||
         memcmp( base64_test_dec, buffer, 64 ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n\n" );

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_BASE64_C */
