/*
 *  RSA simple data encryption program
 *
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

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            fail
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_PK_PARSE_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_FS_IO) && \
    defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <string.h>
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_PK_PARSE_C) ||  \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_PK_PARSE_C and/or "
           "MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit( 0 );
}
#else


int main( int argc, char *argv[] )
{
    mbed_pktop_t  *pk = NULL;
    FILE          *f;
    const char    *pers = "mbed_pk_encap";
    uint8_t        input[1024];
    uint8_t        buf[4096];
    size_t         i, olen = 0;
    int            rc = -1;

    if( argc != 3 )
    {
        mbedtls_printf( "usage: mbed_pk_encap <key_file> <string of max 100 characters>\n" );
#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif
        goto fail;
    }
    
    mbed_pk_init( &pk, mbedtls_ctr_drbg_random, NULL, pers);
    mbedtls_printf( "\n  . Reading public key from '%s'", argv[1] ); fflush( stdout );

    if( ( rc = mbed_pk_parse_pub_keyfile( pk, argv[1] ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbed_pk_parse_pub_keyfile returned -0x%04x\n", (unsigned int) -rc );
        goto fail;
    }

    if( strlen( argv[2] ) > 100 )
    {
        mbedtls_printf( " Input data larger than 100 characters.\n\n" );
        goto fail;
    }
    memcpy( input, argv[2], strlen( argv[2] ) );

    // Calculate the RSA encryption of the hash.
    mbedtls_printf( "\n  . Generating the encrypted value" ); fflush( stdout );

    if ((rc = mbed_pk_encap(pk, MBED_CAPMODE_PKCS1_5, input, strlen(argv[2]), buf, sizeof(buf), &olen)) != 0)
    {
        mbedtls_printf( " failed\n  ! mbed_pk_encap returned -0x%04x\n",  (unsigned int) -rc );
        goto fail;
    }

    // Write the signature into result-enc.txt
    if( ( f = fopen( "result-enc.txt", "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", "result-enc.txt" );
        goto fail;
    }
    for( i = 0; i < olen; i++ )
    {
        mbedtls_fprintf( f, "%02X%s", buf[i], ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
    }

    fclose( f );

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", "result-enc.txt" );
    goto cleanup; // SUCCESS 

fail:
  #if defined(MBEDTLS_ERROR_C)
    mbedtls_strerror( rc, (char *) buf, sizeof( buf ) );
    mbedtls_printf( "  !  Last error was: %s\n", buf );
  #endif
  #if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to fail this program.\n" );   fflush( stdout ); getchar();
  #endif
cleanup: 
    mbed_pk_free( pk );
    mbedtls_exit( MBEDTLS_EXIT_SUCCESS );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_PK_PARSE_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
