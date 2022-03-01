/*
 *  Key generation application
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
#endif /* MBEDTLS_PLATFORM_C */


//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include "mbedtls/error.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_FORMAT              FORMAT_PEM


#if !defined(MBEDTLS_PK_WRITE_C) || !defined(MBEDTLS_PEM_WRITE_C) || \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_PK_WRITE_C and/or MBEDTLS_FS_IO and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_PEM_WRITE_C"
            "not defined.\n" );
    mbedtls_exit( 0 );
}
#else

//----------------------------------------------------------------------------
//----------------- Global variables  ----------------------------------------
//----------------------------------------------------------------------------
static int write_private_key( mbed_pktop_t *key, const char *outfile, int format)
{
    FILE           *f = NULL;
    unsigned char   output_buf[16000];
    unsigned char  *c = output_buf;
    size_t          len = 0;
    int             rc;

    /*---------------------Code ----------------------------------------------*/
    memset(output_buf, 0, 16000);
    if( format == FORMAT_PEM )
    {
        if( ( rc = mbed_pk_write_key_pem( key, output_buf, 16000 ) ) < 0 )
            goto fail;
        len = strlen( (char *) output_buf );
    }
    else
    {
        if( ( rc = mbed_pk_write_key_der( key, output_buf, 16000 ) ) < 0 )
            goto fail;
        len = rc;
        c = output_buf + sizeof(output_buf) - len;
    }

    if( ( f = fopen( outfile, "wb" ) ) == NULL )
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



int main(int argc, char *argv[])
{
    mbed_pktop_t      *pk = NULL;
    const char        *pers = "key_add";
    char               buf[1024];
    char              *p, *q;
    int                format;
    int                i, rc = 1;
    const char        *infile1 = NULL, *infile2 = NULL, *outfile = NULL;


    /*---------------------Code ----------------------------------------------*/
    if (argc == 0)
        goto usage;

    format = DFL_FORMAT;

    for (i = 1; i < argc; i++)
    {
        p = argv[i];
        if ((q = strchr( p, '=' )) == NULL)
            goto usage;
        *q++ = '\0';

        if (strcmp( p, "format" ) == 0)
        {
            if (strcmp( q, "pem" ) == 0)
                format = FORMAT_PEM;
            else if (strcmp( q, "der" ) == 0)
                format = FORMAT_DER;
            else
                goto usage;
        }
        else if (strcmp( p, "infile1" ) == 0)
            infile1 = q;
        else if (strcmp( p, "infile2" ) == 0)
            infile2 = q;
        else if (strcmp( p, "outfile" ) == 0)
            outfile = q;
        else
            goto usage;
    }
    if (infile1 == NULL || infile2 == NULL || outfile == NULL)
    {
        mbedtls_printf( "FAILED: Two input files and one output file must be specified\n" );
        goto usage; 
    }

    // Initialize the pk
    mbed_pk_init( &pk, NULL, NULL, pers );

    // Load the first key
    if ((rc = mbed_pk_parse_prv_keyfile( pk, infile1, "" )) != 0)
        goto fail;
    // Load the second key
    if ((rc = mbed_pk_parse_prv_keyfile( pk, infile2, "" )) != 0)
        goto fail;

    // Export the combined key
    if ((rc = write_private_key( pk, outfile, format )) != 0)
    {
        mbedtls_printf( "FAILED: Writing pk to file %s\n", outfile);
        goto fail;
    }
    mbedtls_printf( "Writing pk to file %s in %s format... ok\n", outfile, (format == FORMAT_PEM) ? "PEM" : "DER" );

    // 1.2 Print the pk information
    mbedtls_printf( "\nKey information:\n" );
    mbedtls_printf( "-----------------------\n" );
    {
        char text_buf[4096];
        if ((rc = mbed_pk_export_key_info( pk, PK_TARGET_PRV, PK_EXPORT_BASIC, text_buf, sizeof(text_buf) )) < 0)
        {
            mbedtls_printf( "FAILED: pk type not supported\n" );
            goto fail;
        }
        mbedtls_printf( "%s\n", text_buf );
    }
    mbedtls_printf( "done...\n\n" );


    rc = MBEDTLS_EXIT_SUCCESS;
    goto cleanup;



fail:
#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror( rc, buf, sizeof(buf) );
    mbedtls_printf( " - %s\n", buf );
#else
    mbedtls_printf( "\n" );
#endif
    rc = MBEDTLS_EXIT_FAILURE;

usage:
    mbedtls_printf( "\nCombine two keys. (Both keys must be either private or public)\n" );
    mbedtls_printf( "Usage: gen_key infile1=<keyfile1> infile2=<keyfile2> outfile=<comb_keyfile> [format=<format>]\n" );
    mbedtls_printf( "Examples:\n" );
    mbedtls_printf( "  %s: infile1=rsa.key infile2=ec.key outfile=comb.key", argv[0]);
    mbedtls_printf( "\n" );

cleanup:
    mbed_pk_free( pk );
#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif
    mbedtls_exit( rc );
}

#endif /* MBEDTLS_PK_WRITE_C && MBEDTLS_PEM_WRITE_C && MBEDTLS_FS_IO &&
        * MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
