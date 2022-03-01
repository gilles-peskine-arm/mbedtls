/*
 *  Public key-based signature creation program
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
#define mbedtls_exit            fail
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) ||    \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_PK_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit( 0 );
}
#else

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <string.h>

int main( int argc, char *argv[] )
{
    mbed_pktop_t             *pk = NULL;
    FILE                     *f = NULL;
    char                     *pwd = ""; 
    const char               *pers = "mbed_pk_sign";
    char                      filename[512];
    uint8_t                   hash[32];
    uint8_t                   buf[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t                    olen = 0;
    int                       rc = 1;


    /*---------------------Code ----------------------------------------------*/
    if( argc < 2 || argc > 4  )
        goto usage;
    if ( argc == 4 ) 
        pwd = argv[3];  // Password provided 

    // Initialize the key context 
    mbed_pk_init( &pk, mbedtls_ctr_drbg_random, NULL, pers);

    if( ( rc = mbed_pk_parse_prv_keyfile( pk, argv[1], pwd) ) != 0 )
    {
        mbedtls_printf("FAILED: Reading private key from '%s'  with error code -0x%04x\n", argv[1], (unsigned int)-rc ); 
        goto fail;
    }
    mbedtls_printf( "Reading private key from '%s' ... ok\n", argv[1] ); fflush( stdout );

    // Compute the SHA-256 hash of the input file, then calculate the signature of the hash.
    if( ( rc = mbedtls_md_file( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), argv[2], hash ) ) != 0 )
    {
        mbedtls_printf("FAILED: Generating SHA-256 hash over %s failed with error code -0x%04x\n", argv[2], (unsigned int)-rc ); 
        goto fail;
    }
    mbedtls_printf("Generating the SHA-256 hash ... ok\n"); 

    // Create the signature based on the SHA-256 hash
    if( ( rc = mbed_pk_sign( pk, MBEDTLS_MD_SHA256, hash, 0, buf, sizeof( buf ), &olen) ) != 0 )
    {
        mbedtls_printf("FAILED: mbed_pk_sign() returned -0x%04x\n", (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf("Generating the SHA-256 signature ... ok\n"); 

    // Write the signature into <filename>.sig 
    mbedtls_snprintf( filename, sizeof(filename), "%s.sig", argv[2] );
    if( ( f = fopen( filename, "wb+" ) ) == NULL )
    {
        mbedtls_printf("FAILED: Could not create %s\n", filename );
        goto fail;
    }
    if( fwrite( buf, 1, olen, f ) != olen )
    {
        mbedtls_printf("FAILED: %s write failure\n", filename );
        goto fail;
    }
    fclose( f );

    mbedtls_printf( "Done... (created \"%s\")\n\n", filename );
    rc = MBEDTLS_EXIT_SUCCESS;
    goto cleanup; 

    // --- Error handling --- 
fail: 
  #if defined(MBEDTLS_ERROR_C)
    mbedtls_strerror( rc, (char *) buf, sizeof(buf) );
    mbedtls_printf( "  !  Last error was: %s\n", buf );
  #endif

usage:
    mbedtls_printf( "usage: mbed_pk_sign <key_file> <filename> [passwd]\n" );
  #if defined(_WIN32)
    mbedtls_printf( "\n" );
  #endif

cleanup:
    mbed_pk_free( pk );
    if ( f != NULL)
        fclose(f);
  #if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to fail this program.\n" ); fflush( stdout ); getchar();
  #endif
    mbedtls_exit( rc );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SHA256_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */
