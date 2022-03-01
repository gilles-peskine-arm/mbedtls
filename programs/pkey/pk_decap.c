/*
 *  Public key-based simple decryption program
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
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_PK_PARSE_C) &&  defined(MBEDTLS_FS_IO) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <string.h>
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_PK_PARSE_C and/or "
                   "MBEDTLS_FS_IO and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit( 0 );
}
#else


int main( int argc, char *argv[] )
{
    mbed_pktop_t  *pk = NULL;
    FILE          *f;
    const char    *pers = "mbed_pk_decap";
    uint8_t        result[1024];
    uint8_t        buf[4096];
    unsigned       c;
    size_t         i, olen = 0;
    int            rc = -1;


    /*---------------------Code ----------------------------------------------*/
    memset(result, 0, sizeof( result ) );
    if( argc != 2 )
    {
        mbedtls_printf( "usage: mbed_pk_decap <key_file>\n" );
#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif
        goto fail;
    }

    mbed_pk_init( &pk, mbedtls_ctr_drbg_random, NULL, pers);

    mbedtls_printf( "\n  . Reading private key from '%s'", argv[1] ); fflush( stdout );
    if( ( rc = mbed_pk_parse_prv_keyfile( pk, argv[1], "") ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbed_pk_parse_prv_keyfile returned -0x%04x\n", (unsigned int) -rc );
        goto fail;
    }

    // Extract the RSA encrypted value from the text file 
    if( ( f = fopen( "result-enc.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open file: %s\n\n", "result-enc.txt" );
        rc = 1;
        goto fail;
    }
    i = 0;
    while( fscanf( f, "%02X", (unsigned int*) &c ) > 0 && i < (int) sizeof( buf ) )
    {
        buf[i++] = (uint8_t) c;
    }
    fclose(f);

    // Decrypt the encrypted RSA data and print the result.
    mbedtls_printf( "\n  . Decrypting the encrypted data" ); fflush( stdout );

    if( ( rc = mbed_pk_decap( pk, MBED_CAPMODE_PKCS1_5, buf, i, result, sizeof(result), &olen) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbed_pk_decap returned -0x%04x\n", (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf( "\n  . OK\n\n" );
    mbedtls_printf( "The decrypted result is: '%s'\n\n", result );

    // SUCCESS 
    goto cleanup; 

fail: 
  #if defined(MBEDTLS_ERROR_C)
    mbedtls_strerror( rc, (char *) buf, sizeof( buf ) );
    mbedtls_printf( "  !  Last error was: %s\n", buf );
  #endif
  #if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
  #endif
cleanup:
    mbed_pk_free( pk );
    mbedtls_exit( MBEDTLS_EXIT_SUCCESS );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
