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

/******************************************************************************
 * Description: Move file data into an allocated buffer
 *
 * Arguments:   path     - file path
 *              size     - container for the size of the allocated buffer
 *
 * result:      Pointer to the allocated buffer
 *              NOTE: The allocated buffer must be freed by caller
 *****************************************************************************/
uint8_t *util_file2bufAlloc(const char *path, size_t *size )
{
    FILE     *fp = NULL;
    uint8_t  *buf = NULL;
    size_t    bytes_read, fsize;


    //--------- code ----------------------------------------------------------
    if( (fp = fopen(path, "rb")) == NULL)
    {
        mbedtls_printf( " failed\n  ! Cannot open file %s\n",path);
        goto Fail;
    }
    // find the size of the file
    fseek(fp, 0, SEEK_END);
    fsize = ftell( fp);
    if ( (buf = (uint8_t*)malloc(fsize)) == NULL)
         goto Fail;

    // Move file pinter back to the beginning
    fseek(fp, 0, SEEK_SET);
    bytes_read = fread(buf, 1, fsize, fp);
    fclose(fp);
    if ( bytes_read != fsize )
        goto Fail;
    *size = fsize;
    return buf;

Fail:
    if( fp != NULL )
        fclose(fp);
    if ( buf != NULL )
        free(buf);
    return 0;
}


static void util_dump( const void *data_in, uint32_t length, const char *prompt)
{
    const uint8_t  *data = (const uint8_t *)data_in; 
    unsigned int    i;

    if (prompt)
    {
        fprintf(stdout, "%s: (size=%d)  ", prompt, (int)length);
    }
    for (i = 0; i < length; ++i)
    {
        if ( (i % 32 == 0) && (length > 32) )
        {
            fprintf(stdout, "\n\t");
        }
        fprintf(stdout, "%02x, ", data[i]);
    }
    fprintf(stdout, "\n");
}


/******************************************************************************
 * Description: Main: Generate KEM message 
 *  
 * result:      0/ -1 
 *****************************************************************************/
int main( int argc, char *argv[] )
{
    mbed_pktop_t  *pk = NULL;
    const char    *pers = "mbed_pk_kemgen";
    char          *fname_kem, *fname_shared_cmp, *fname_key; 
    uint8_t        buf[512 ];            // error message
    uint8_t       *kem = NULL;           // kem data from file
    uint8_t       *shared_cmp = NULL;    // shared secret from file 
    uint8_t        shared[3 * 64];       // shared secret  
    size_t         shared_cmp_size = 0, sh_olen = 0, kem_consumed = 0, kem_size = 0;
    int            rc = -1;

    /*---------------------Code ----------------------------------------------*/
    if( argc != 2 )
    {
        mbedtls_printf( "usage: mbed_pk_encap <private_key_file>\n" );
#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif
        goto fail;
    }
    fname_key  =  argv[1];
    
    // --- initialize the key context for the private and peer keys 
    mbed_pk_init( &pk, mbedtls_ctr_drbg_random, NULL, pers);

    // --- Reading the private key 
    mbedtls_printf( "\n  . Reading private key from '%s'",fname_key ); fflush( stdout );
    if( ( rc = mbed_pk_parse_prv_keyfile( pk, argv[1], "" ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbed_pk_parse_keyfile '%s' returned -0x%04x\n", fname_key, (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf( " ok" );

    // ---Read the KEM data 
    fname_kem = "result-kem.bin";
    mbedtls_printf( "\n  . Read KEM data from file %s",fname_kem); fflush( stdout );
    if( ( kem = (uint8_t*)util_file2bufAlloc(fname_kem, &kem_size)) == 0) 
    {
        mbedtls_printf( " failed\n  ! Read from file %s\n\n", fname_kem );
        goto fail;
    }
    mbedtls_printf( " ok" );

    // --- Read shared secret data to compare against 
    fname_shared_cmp = "result-shared.bin";
    mbedtls_printf( "\n  . Read shared compare data from file %s",fname_shared_cmp); fflush( stdout );
    if( ( shared_cmp = (uint8_t*)util_file2bufAlloc(fname_shared_cmp, &shared_cmp_size)) == 0) 
    {
        mbedtls_printf( " failed\n  ! Read from file %s\n\n", fname_shared_cmp );
        goto fail;
    }
    mbedtls_printf( " ok" );

    // --- Extract the shared secret from the KEM data 
    mbedtls_printf( "\n  . Generating the kem message" ); fflush( stdout );
    if ((rc = mbed_pk_kem_extract( pk, MBED_CAPMODE_NONE, 1024, shared, sizeof(shared), &sh_olen, kem, kem_size, &kem_consumed)) != 0)
    {
        mbedtls_printf( " failed\n  ! mbed_pk_kem_extract returned -0x%04x\n", (unsigned int) -rc );
        goto fail;
    }
    if (kem_consumed != kem_size)
        mbedtls_printf( " WARNING\n  ! kem data in file (len=%d) is larger than used (len=%d)\n", (int)kem_size, (int)kem_consumed);
    else 
        mbedtls_printf( " ok" );

    mbedtls_printf( "\n  . Compare extracted shared secret with the version on file" ); fflush( stdout );
    if (sh_olen != shared_cmp_size || memcmp(shared, shared_cmp, shared_cmp_size) != 0) 
    {
        mbedtls_printf( " FAILED\n  ! Shared secret mismatch\n");
        util_dump(shared, sh_olen,"shared secret extracted from kem");
        util_dump(shared_cmp, shared_cmp_size,"shared secret from file");
        rc = -1; 
        goto fail;
    }
    mbedtls_printf( " ok\n" );
    util_dump(shared, sh_olen,"shared secret extracted from kem");

    mbedtls_printf( "\n  . Done (verified shared secret from files \"%s\" and \"%s\")\n\n", fname_kem, fname_shared_cmp);
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
    if (kem != NULL) free(kem);
    if (shared_cmp != NULL) free(shared_cmp);
    mbed_pk_free( pk );
    mbedtls_exit( MBEDTLS_EXIT_SUCCESS );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_PK_PARSE_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
