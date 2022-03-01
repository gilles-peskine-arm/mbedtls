/*
 *  Key writing application
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



#if !defined(MBEDTLS_PK_PARSE_C) || \
    !defined(MBEDTLS_PK_WRITE_C) || \
    !defined(MBEDTLS_FS_IO)      || \
    !defined(MBEDTLS_ENTROPY_C)  || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_PK_PARSE_C and/or MBEDTLS_PK_WRITE_C and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
                    "MBEDTLS_FS_IO not defined.\n" );
    mbedtls_exit( 0 );
}

#else

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <string.h>

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#if defined(MBEDTLS_PEM_WRITE_C)
#define DFL_OUTPUT_FILENAME     "keyfile.pem"
#define DFL_OUTPUT_FORMAT       OUTPUT_FORMAT_PEM
#else
#define DFL_OUTPUT_FILENAME     "keyfile.der"
#define DFL_OUTPUT_FORMAT       OUTPUT_FORMAT_DER
#endif

#define DFL_MODE                MODE_NONE
#define DFL_FILENAME            "keyfile.key"
#define DFL_DEBUG_LEVEL         0
#define DFL_OUTPUT_MODE         OUTPUT_MODE_NONE

#define MODE_NONE               0
#define MODE_PRIVATE            1
#define MODE_PUBLIC             2

#define OUTPUT_MODE_NONE               0
#define OUTPUT_MODE_PRIVATE            1
#define OUTPUT_MODE_PUBLIC             2

#define OUTPUT_FORMAT_PEM              0
#define OUTPUT_FORMAT_DER              1


static int write_public_key( mbed_pktop_t *pk, const char *outfile, int outformat)
{
    FILE     *f = NULL;
    uint8_t   output_buf[16000];
    uint8_t  *c = output_buf;
    size_t    len = 0;
    int       rc;

    /*---------------------Code ----------------------------------------------*/
    memset(output_buf, 0, 16000);

  #if defined(MBEDTLS_PEM_WRITE_C)
    if( outformat == OUTPUT_FORMAT_PEM )
    {
        mbedtls_printf("Output format is PEM\n");
        if( ( rc = mbed_pk_write_pubkey_pem( pk, output_buf, 16000 ) ) < 0 ) 
            goto fail;
        len = strlen( (char *) output_buf );
    }
    else
  #endif
    {
        mbedtls_printf("Output format is DER\n");
        if( ( rc = mbed_pk_write_pubkey_der( pk, output_buf, 16000 ) ) < 0 )
            goto fail;

        len = rc;
        c = output_buf + sizeof(output_buf) - len;
    }

    if( ( f = fopen( outfile, "w" ) ) == NULL )
        goto fail_fwrite;

    if( fwrite( c, 1, len, f ) != len )
        goto fail_fwrite;
    fclose( f );
    return( 0 );

fail_fwrite: 
    rc = -1; 
fail: 
    if ( f != NULL)
        fclose( f );
    return rc; 
}

static int write_private_key( mbed_pktop_t *pk, const char *outfile, int outformat )
{
    FILE     *f = NULL;
    uint8_t   output_buf[16000];
    uint8_t  *c = output_buf;
    size_t    len = 0;
    int       rc;

    /*---------------------Code ----------------------------------------------*/
    memset(output_buf, 0, 16000);

  #if defined(MBEDTLS_PEM_WRITE_C)
    if( outformat == OUTPUT_FORMAT_PEM )
    {
        mbedtls_printf("Output format is PEM\n");
        if( ( rc = mbed_pk_write_key_pem( pk, output_buf, 16000 ) ) < 0 ) 
            goto fail;
        len = strlen( (char *) output_buf );
    }
    else
  #endif
    {
        mbedtls_printf("Output format is DER\n");
        if( ( rc = mbed_pk_write_key_der( pk, output_buf, 16000 ) ) < 0 )
            goto fail;
        len = rc;
        c = output_buf + sizeof(output_buf) - len;
    }

    if( ( f = fopen( outfile, "w" ) ) == NULL )
        goto fail_fwrite;

    if( fwrite( c, 1, len, f ) != len )
        goto fail_fwrite;
    fclose( f );
    return( 0 );

fail_fwrite: 
    rc = -1; 
fail: 
    if ( f != NULL)
        fclose( f );
    return rc; 
}


//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------- Main code ------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

int main( int argc, char *argv[] )
{
    mbed_pktop_t    *pk = NULL,  *subkey = NULL, *export_key;
    mbed_pktarget_e  target;
    char             text_buf[4096];
    char             buf[1024];
    char            *p, *q;
    const char      *pers = "pkey/key_app";
    int              i, key_idx = 0;
    int              rc = 1;
    int              mode;        // The mode to run the application in
    const char      *fname;       // File name of the key file
    int              outmode;     // The output mode to use
    const char      *outfile;     // Where to store the constructed key file
    int              outformat;   // The output format to use


    /*---------------------Code ----------------------------------------------*/
    // Set to sane values
    memset(buf, 0, sizeof(buf));
    if (argc < 2)
        goto usage;

    mode                = DFL_MODE;
    fname               = DFL_FILENAME;
    outmode             = DFL_OUTPUT_MODE;
    outfile             = DFL_OUTPUT_FILENAME;
    outformat           = DFL_OUTPUT_FORMAT;

    // Parse the arguments
    for (i = 1; i < argc; i++)
    {
        p = argv[i];
        if ((q = strchr( p, '=' )) == NULL)
            goto usage;
        *q++ = '\0';

        // printf("p=%s, q=%s\n", p, q);
        if (strcmp( p, "mode" ) == 0)
        {
            if (strcmp( q, "private" ) == 0)
                mode = MODE_PRIVATE;
            else if (strcmp( q, "public" ) == 0)
                mode = MODE_PUBLIC;
            else
                goto usage;
        }
        else if (strcmp( p, "outmode" ) == 0)
        {
            if (strcmp( q, "private" ) == 0)
                outmode = OUTPUT_MODE_PRIVATE;
            else if (strcmp( q, "public" ) == 0)
                outmode = OUTPUT_MODE_PUBLIC;
            else
                goto usage;
        }
        else if (strcmp( p, "outformat" ) == 0)
        {
          #if defined(MBEDTLS_PEM_WRITE_C)
            if (strcmp( q, "pem" ) == 0)
                outformat = OUTPUT_FORMAT_PEM;
            else
          #endif
                if (strcmp( q, "der" ) == 0)
                    outformat = OUTPUT_FORMAT_DER;
                else
                    goto usage;
        }
        else if (strcmp( p, "infile" ) == 0)
            fname = q;
        else if (strcmp( p, "outfile" ) == 0)
            outfile = q;
        else if (strcmp( p, "idx" ) == 0)
        {
            key_idx = atoi( q );
            if (key_idx < 0 || key_idx >= 3)
                goto usage;
        }
        else
            goto usage;
    }

    if (mode == MODE_NONE)
    {
        mbedtls_printf( "\nCannot output a pk without reading one.\n" );
        goto fail;
    }
    if (outmode == MODE_NONE)
    {
        mbedtls_printf( "\nNeed to select an output mode.\n" );
        goto fail;
    }
    if (mode == MODE_PUBLIC && outmode == OUTPUT_MODE_PRIVATE)
    {
        mbedtls_printf( "\nCannot output a private pk from a public pk.\n" );
        goto fail;
    }
    if (outmode == MODE_PRIVATE)
        target = PK_TARGET_PRV;
    else
        target = PK_TARGET_PUB;


    mbed_pk_init(&pk, mbedtls_ctr_drbg_random, NULL, pers);
    if (mode == MODE_PRIVATE)
    {
        // 1.1. Load the pk
        mbedtls_printf( "\nLoading the private key ... " ); fflush( stdout );
        rc = mbed_pk_parse_prv_keyfile( pk, fname, NULL );
    }
    else if (mode == MODE_PUBLIC)
    {
        // 1.1. Load the pk
        mbedtls_printf( "\nLoading the public key ..." ); fflush( stdout );
        rc = mbed_pk_parse_pub_keyfile( pk, fname );
    }
    if (rc != 0)
    {
        mbedtls_strerror( rc, (char *)buf, sizeof(buf) );
        mbedtls_printf( " failed\nmbed_pk_parse_prv_keyfile() returned -0x%04x - %s\n\n", (unsigned int)-rc, buf );
        goto fail;
    }
    mbedtls_printf(" ok\n");

    // 1.3 Write the pk
    export_key = pk; 
    if (key_idx != 0)
    {
        // Use the hidden 'mbed_pk_create_subkey_ref' API.
        // WARNING: a subkey is a reference to a real topkey key index
        //          and can ONLY be used to export DER or text info and
        //          is valid only as long as the main key is valid.
        //          Do NOT use this API in any other way.
        int mbed_pk_create_subkey_ref( mbed_pktop_t * pktop_ref, mbed_pktop_t * subkey_top_ref, int key_idx );
     
        mbed_pk_init( &subkey, NULL, NULL, NULL );
        if ((rc = mbed_pk_create_subkey_ref( pk, subkey, key_idx )) < 0)
        {
            mbedtls_printf( " failed\n  ! key_idx %d not found\n", key_idx );
            goto fail;
        }
        export_key = subkey; 
    }

    if (outmode == OUTPUT_MODE_PUBLIC)
        rc = write_public_key( export_key, outfile, outformat );
    else if (outmode == OUTPUT_MODE_PRIVATE)
        rc = write_private_key( export_key, outfile, outformat );
    if (rc < 0) {
        mbedtls_printf("Create output file %s ... failed\n", outfile);
        mbedtls_printf("Write key file returned -0x%04x - %s\n\n", (unsigned int)-rc, buf );
        goto fail;
    }
    mbedtls_printf( "\nCreate output file %s ... ok\n", outfile); fflush( stdout );

    // 1.3 Print the pk information
    mbedtls_printf("\nKey information:\n");
    mbedtls_printf("-----------------------\n");
    if(mbed_pk_export_key_info(export_key, target, PK_EXPORT_BASIC, text_buf, sizeof(text_buf)) < 0)
    {
        mbedtls_printf("FAILED: Export key information\n");
        goto usage;
    }
    mbedtls_printf("%s\n", text_buf);
   

    // We are done
    rc = MBEDTLS_EXIT_SUCCESS;
    goto cleanup;


fail:
  #ifdef MBEDTLS_ERROR_C
    mbedtls_strerror( rc, buf, sizeof( buf ) );
    mbedtls_printf( " - %s\n", buf );
  #else
    mbedtls_printf("\n");
  #endif
  rc = 1; 

usage:
    mbedtls_printf("\n usage: key_conversion param=<>...\n");
    mbedtls_printf("\n acceptable parameters:\n");
    mbedtls_printf("    mode=private|public        default: none\n");
    mbedtls_printf("    infile=<keyfile_in>        default: keyfile.key\n");
    mbedtls_printf("    idx=<pk index(0-3)>        default: 0 (all keys converted)\n");
    mbedtls_printf("    outmode=private|public     default: none\n");
  #if defined(MBEDTLS_PEM_WRITE_C)
    mbedtls_printf("    outfile=<keyfile_out>      default: keyfile.pem\n");
    mbedtls_printf("    outformat=pem|der          default: pem\n");
#else
    mbedtls_printf("    outfile=<keyfile_out>      default: keyfile.der\n");
    mbedtls_printf("    outformat=der              default: der\n");
#endif

cleanup:
    if ( subkey != NULL)
        free( subkey ); // This is not a real key, only the top context structure exists

    mbed_pk_free( pk );
  #if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to fail this program.\n" );
    fflush( stdout ); getchar();
  #endif
    mbedtls_exit( rc );
}
#endif /* MBEDTLS_PK_PARSE_C && MBEDTLS_PK_WRITE_C && MBEDTLS_FS_IO &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
