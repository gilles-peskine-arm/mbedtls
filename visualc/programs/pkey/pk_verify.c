/*
 *  Public key-based signature verification program
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
#define mbedtls_snprintf        snprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_PK_PARSE_C) ||   \
    !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_PK_PARSE_C and/or "
           "MBEDTLS_FS_IO not defined.\n");
    mbedtls_exit( 0 );
}
#else

#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <string.h>


int main( int argc, char *argv[] )
{
    mbed_pktop_t   *pk = NULL;
    char            filename[512];
    uint8_t         hash[32];
    uint8_t         buf[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    FILE           *f;
    size_t          i;
    int             rc = 1;


    /*---------------------Code ----------------------------------------------*/
    mbed_pk_init( &pk, NULL, NULL, NULL );
    if( argc != 3 )
        goto usage; 
    fflush( stdout );

    if( ( rc = mbed_pk_parse_pub_keyfile( pk, argv[1] ) ) != 0 )
    {
        mbedtls_printf( "FAILED: read public key '%s'\nmbed_pk_parse_pub_keyfile() returned -0x%04x\n", argv[1], (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf("Reading public key from '%s' ... ok\n", argv[1] );

    // Extract the signature from the file
    mbedtls_snprintf( filename, sizeof(filename), "%s.sig", argv[2] );
    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf("FAILED: Could not open %s\n", filename );
        goto fail;
    }
    i = fread( buf, 1, sizeof(buf), f );
    fclose( f );

    // Compute the SHA-256 hash of the input file and
    // verify the signature
    if( ( rc = mbedtls_md_file( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), argv[2], hash ) ) != 0 )
    {
        mbedtls_printf("FAILED: Generating SHA-256 hash over %s failed with error code -0x%04x\n", argv[2], (unsigned int)-rc ); 
        goto fail;
    }
    mbedtls_printf("Generating the SHA-256 hash ... ok\n"); 

    if( ( rc = mbed_pk_verify( pk, MBEDTLS_MD_SHA256, hash, 0, buf, i ) ) != 0 )
    {
        mbedtls_printf("FAILED: mbed_pk_verify() returned -0x%04x\n", (unsigned int) -rc );
        goto fail;
    }

    mbedtls_printf( "\nOK (the signature is valid)\n\n" );
    rc = MBEDTLS_EXIT_SUCCESS;
    goto cleanup; 

    // --- Error handling --- 
fail: 
  #if defined(MBEDTLS_ERROR_C)
    mbedtls_strerror( rc, (char *) buf, sizeof(buf) );
    mbedtls_printf( "  !  Last error was: %s\n", buf );
  #endif
usage:
    mbedtls_printf( "\nusage: mbed_pk_verify <key_file> <filename>\n" );
  #if defined(_WIN32)
    mbedtls_printf( "\n" );
  #endif
cleanup:
    mbed_pk_free( pk );
  #if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
  #endif
    mbedtls_exit( rc );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_SHA256_C &&
          MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO */
