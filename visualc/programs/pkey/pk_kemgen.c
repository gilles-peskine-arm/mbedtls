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
 * Description: Write buffer data to a file
 *              NOTE: Existing file data WILL be overwritten
 *
 * Arguments:   path     - file path
 *              buf      - pointer to the data
 *              len      - data length
 *
 * result:      Number of bytes_written / 0
 *****************************************************************************/
static size_t  util_buf2file(const char *path,  uint8_t *buf, size_t len )
{
    FILE     *fp = NULL;
    size_t    bytes_written;


    //--------- code ----------------------------------------------------------
    if( (fp = fopen(path, "wb")) == NULL)
    {
        mbedtls_printf( " failed\n  ! Cannot open file %s\n",path);
        goto Fail;
    }
    bytes_written = fwrite( buf, 1, len, fp);
    fclose(fp);
    if( bytes_written != len)
        goto Fail;
    return bytes_written;

Fail:
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
    mbed_pktop_t  *pk = NULL, *pk_peer = NULL;
    const char    *pers = "mbed_pk_kemgen";
    char          *fname_kem, *fname_shared, *fname_key, *fname_peer; 
    uint8_t        buf[512 ];   // error message
    uint8_t        kem[4096];   // kem message 
    uint8_t        shared[3 * 64];  // shared secret  
    size_t         sh_olen = 0, kem_olen = 0;
    int            rc = -1;

    /*---------------------Code ----------------------------------------------*/
    if( argc != 3 )
    {
        mbedtls_printf( "usage: mbed_pk_encap <private_key_file> <peer public_key_file>\n" );
#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif
        goto fail;
    }
    fname_key  =  argv[1];
    fname_peer =  argv[2];
    
    // --- initialize the key context for the private and peer keys 
    mbed_pk_init( &pk, mbedtls_ctr_drbg_random, NULL, pers);
    mbed_pk_init( &pk_peer, mbedtls_ctr_drbg_random, NULL, pers);

    // --- Reading the private key 
    mbedtls_printf( "\n  . Reading private key from '%s'",fname_key ); fflush( stdout );
    if( ( rc = mbed_pk_parse_prv_keyfile( pk, argv[1], "" ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbed_pk_parse_keyfile '%s' returned -0x%04x\n", fname_key, (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf( " ok" );

    // --- Reading the peer public key 
    mbedtls_printf( "\n  . Reading peer public key from '%s'",  fname_peer); fflush( stdout );
    if( ( rc = mbed_pk_parse_pub_keyfile( pk_peer, fname_peer) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbed_pk_parse_pub_keyfile '%s' returned -0x%04x\n", fname_peer, (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf( " ok" );

    // ---Generate the KEM data 
    mbedtls_printf( "\n  . Generating the kem message" ); fflush( stdout );
    if ((rc = mbed_pk_kem_gen( pk, pk_peer, MBED_CAPMODE_NONE, 1024, shared, sizeof(shared), &sh_olen, 
                                                                     kem, sizeof(kem), &kem_olen)) != 0)
    {
        mbedtls_printf( " failed\n  ! mbed_pk_kem_gen returned -0x%04x\n", (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf( " ok" );

    // ---Write the KEM data 
    fname_kem = "result-kem.bin";
    mbedtls_printf( "\n  . Write kem message to file %s",fname_kem); fflush( stdout );
    if ( util_buf2file(fname_kem, kem, kem_olen) == 0) 
    {
        mbedtls_printf( " failed\n  ! Write to file %s\n\n", fname_kem );
        goto fail;
    }
    mbedtls_printf( " ok" );

    // --- Write shared secret data 
    fname_shared = "result-shared.bin";
    mbedtls_printf( "\n  . Write shared secret to file %s",fname_shared); fflush( stdout );
    if ( util_buf2file( fname_shared, shared, sh_olen) == 0) 
    {
        mbedtls_printf( " failed\n  ! Write to file %s\n\n", fname_shared );
        goto fail;
    }
    mbedtls_printf( " ok\n" );

    util_dump(shared, sh_olen,"Shared secret");

    mbedtls_printf( "\n  . Done (created \"%s\" and \"%s\")\n\n", fname_kem, fname_shared);
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
    mbed_pk_free( pk_peer );
    mbedtls_exit( MBEDTLS_EXIT_SUCCESS );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_PK_PARSE_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
