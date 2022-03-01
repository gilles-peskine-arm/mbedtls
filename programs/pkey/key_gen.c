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
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_FS_IO) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>

#define DEV_RANDOM_THRESHOLD        32

typedef struct 
{
    mbed_entropy_cb_t  entropy_cb;  
    size_t             threshold; 
    size_t             strong; 
    int                initialized; 
} devrandom_info_t; 

static devrandom_info_t  devrand;  // global variable 

void print_usage(char **argv)
{
    mbedtls_printf("\nGenerate a public key\n");
    mbedtls_printf("usage: gen_key <parameters...>\n");
    mbedtls_printf("acceptable parameters:\n");
    mbedtls_printf("    type=rsa|ec|dilithium|kyber  default: rsa\n");      
    mbedtls_printf("    outfile=<key file>           default: keyfile.key\n");
    mbedtls_printf("    addkey=<existing file>       add pk to file (hybrid pk)\n");
    mbedtls_printf("    format=pem|der               default: pem\n");
  #if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
    mbedtls_printf("    dev_random=Y/N               default: N\n");
  #endif 
    mbedtls_printf("    params=                      key parameter format 'tag1=val1:tag2=val2:..'\n");
    mbedtls_printf("      params examples:\n");
    mbedtls_printf("        RSA: params='size=2048:exp=3'   default: size=3072,exp=65537\n");
    mbedtls_printf("        EC:  params='curve=secp384r1'   default: curve=secp256r1\n");
    mbedtls_printf("  Examples:\n");
    mbedtls_printf("    %s: type=rsa outfile=rsa.key format=der params='size=2048'\n", argv[0]);
    mbedtls_printf("    %s: type=ec outfile=ec.key params='curve=secp256r1'\n", argv[0]);
    mbedtls_printf("\n");
}


int dev_random_entropy_poll( void *data, unsigned char *output, size_t len, size_t *olen ) 
{
    FILE *file;
    size_t ret, left = len;
    unsigned char *p = output;
    ((void) data);

    *olen = 0;

    file = fopen( "/dev/random", "rb" );
    if( file == NULL )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    while( left > 0 )
    {
        /* /dev/random can return much less than requested. If so, try again */
        ret = fread( p, 1, left, file );
        if( ret == 0 && ferror( file ) )
        {
            fclose( file );
            return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
        }

        p += ret;
        left -= ret;
        if ( left != 0 )
            sleep( 1 );
    }
    fclose( file );
    *olen = len;

    return( 0 );
}


int keygen_devrandom_entropy_cb( void *data, unsigned char *output, size_t len ) 
{
    mbedtls_entropy_context  *entropy = (mbedtls_entropy_context *)data;
    int                       rc;


    /*---------------------Code ----------------------------------------------*/
    if (devrand.initialized == 0)
    {
        // If dev random is selected the dev/random source of randomness is used. 
        rc = mbedtls_entropy_add_source( entropy, dev_random_entropy_poll, NULL, devrand.threshold, devrand.strong);
        if (rc != 0)
            goto fail;
        devrand.initialized = 1; 
    }
    // Call the actual entropy callback function 
    devrand.entropy_cb( entropy, output, len);   
    return 0; 

fail: 
    return rc; 
} 
#endif /* !_WIN32 */
#endif

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#if defined(MBEDTLS_ECP_C)
#define DFL_EC_CURVE            mbedtls_ecp_curve_list()->MBEDTLS_PRIVATE(grp_id)
#else
#define DFL_EC_CURVE            0
#endif

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                MBEDTLS_PK_DILITHIUM
#define DFL_FILENAME            "keyfile.key"
#define DFL_FORMAT              FORMAT_PEM
#define DFL_USE_DEV_RANDOM      'N'


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
static int write_private_key( mbed_pktop_t *key, const char *output_file, int format)
{
    unsigned char   output_buf[32*1024];
    FILE           *f = NULL;
    unsigned char  *c;
    size_t          obuf_size, len = 0;
    int             rc;

    /*---------------------Code ----------------------------------------------*/
    obuf_size = sizeof(output_buf); 
    c = output_buf;
    memset(output_buf, 0, 32*1024);
    if( format == FORMAT_PEM )
    {
        if( ( rc = mbed_pk_write_key_pem( key, output_buf, obuf_size ) ) < 0 )
            goto fail;
        len = strlen( (char *) output_buf );
    }
    else
    {
        if( ( rc = mbed_pk_write_key_der( key, output_buf, obuf_size ) ) < 0 )
            goto fail;
        len = rc;
        c = output_buf + obuf_size - len;
    }

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
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



int main( int argc, char *argv[] )
{
    mbed_pktop_t      *pk = NULL;
    mbed_entropy_cb_t  entropy_cb;
    const char        *pers = "gen_key";
    char               buf[1024];
    char              *keygen_params = "";
    char              *p, *q; 
    int                i, rc=1;    
    const char        *fname;                // name of the pk file                
    const char        *addkey_fname = NULL;  // fname of the existing pk file      
    int                pktype;               // the type of pk to generate         
    int                format;               // the output format to use            
    char               dev_random;           // use /dev/random as entropy source       

    /*---------------------Code ----------------------------------------------*/
    // Set to sane values
    memset( buf, 0, sizeof( buf ) );

    if( argc == 0 )
        goto usage; 

    pktype         = DFL_TYPE;
    fname          = DFL_FILENAME;
    format         = DFL_FORMAT;
    dev_random     = DFL_USE_DEV_RANDOM;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "type" ) == 0 )
        {
            if( strcmp( q, "rsa" ) == 0 )
                pktype = MBEDTLS_PK_RSA;
            else if( strcmp( q, "ec" ) == 0 )
                pktype = MBEDTLS_PK_ECKEY;
            else if( strcmp( q, "dilithium" ) == 0 )
                pktype = MBEDTLS_PK_DILITHIUM;
            else if( strcmp( q, "kyber" ) == 0 )
                pktype = MBEDTLS_PK_KYBER;
            else
                goto usage;
        }
        else if( strcmp( p, "format" ) == 0 )
        {
            if( strcmp( q, "pem" ) == 0 )
                format = FORMAT_PEM;
            else if( strcmp( q, "der" ) == 0 )
                format = FORMAT_DER;
            else
                goto usage;
        }
        else if( strcmp( p, "outfile" ) == 0 )
            fname = q;
        else if( strcmp( p, "addkey" ) == 0 )
            addkey_fname = q;
     #if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
        else if( strcmp( p, "dev_random" ) == 0 )
        {
            dev_random = q[0];
            if ( (strlen(q) != 1) || (dev_random != 'Y' && dev_random != 'N'))
                goto usage;
        }
      #endif 
        else if( strcmp( p, "params" ) == 0 ) 
        {
            //len = strlen(q);
            //if ((len < 2 ) ||  (q[0] != '\'' && q[len - 2] != '\''))
            //    goto usage;
            //q[len-2] = '\0';
            //keygen_params = q+1;
            keygen_params = q;
        }
        else
            goto usage;
    }

    entropy_cb = mbedtls_entropy_func; 

  #if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
    if( dev_random == 'Y' ) 
    {
        // If dev random is selected the dev/random source of randomness is used. 
        devrand.entropy_cb  = mbedtls_entropy_func; 
        devrand.threshold   = DEV_RANDOM_THRESHOLD; 
        devrand.strong      = MBEDTLS_ENTROPY_SOURCE_STRONG; 
        devrand.initialized = 0; 

        entropy_cb = keygen_devrandom_entropy_cb; 
    }
  #endif /* !_WIN32 && MBEDTLS_FS_IO */
    
    // Initialize the pk 
    mbed_pk_init( &pk, mbedtls_ctr_drbg_random, entropy_cb, pers);

    if ( addkey_fname != NULL )
    {
        if ((rc=mbed_pk_parse_prv_keyfile(pk, addkey_fname, "")) != 0) 
            goto fail;
    }

    // 1.1 Generate the (private) pk
    if ((rc = mbed_pk_keygen( pk, (mbed_hybpk_t)pktype, keygen_params )) != 0)
    {
        mbedtls_printf( "FAILED: Generating private key, mbed_pk_keygen() returned -0x%04x", (unsigned int)-rc );
        goto fail;
    }
    mbedtls_printf( "Generating the private key ... ok\n" ); fflush( stdout );

    // 1.1 Export pk
    if ((rc = write_private_key( pk, fname, format )) != 0)
    {
        mbedtls_printf( "FAILED: Writing pk to file %s\n", fname );fflush(stdout);
        goto fail;
    }
    mbedtls_printf( "Writing pk to file %s ... ok\n", fname ); fflush(stdout);

    // 1.2 Print the pk information
    mbedtls_printf( "\nKey information:\n" );fflush(stdout);
    mbedtls_printf( "-----------------------\n" );fflush(stdout);
    {
        char text_buf[16*1024];
        if ((rc = mbed_pk_export_key_info( pk, PK_TARGET_PRV, PK_EXPORT_BASIC, text_buf, sizeof(text_buf) )) < 0)
        {
            mbedtls_printf( "FAILED: pk type not supported\n" );
            goto cleanup;
        }
        mbedtls_printf( "%s\n",text_buf);
    }
    mbedtls_printf( "done...\n\n" );


    rc = MBEDTLS_EXIT_SUCCESS;
    goto cleanup; 



fail:
#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror( rc, buf, sizeof( buf ) );
    mbedtls_printf( " - %s\n", buf );
#else
    mbedtls_printf("\n");
#endif
    rc = MBEDTLS_EXIT_FAILURE;
    goto cleanup; 

usage:
    print_usage(argv); 

  #if defined(MBEDTLS_ECP_C)
    // if ( pktype == MBEDTLS_PK_ECKEY) 
    {
        const mbedtls_ecp_curve_info *curve_info;
        mbedtls_printf( " available ec_curve values:\n" );
        curve_info = mbedtls_ecp_curve_list();
        mbedtls_printf( "    %s (default)\n", curve_info->MBEDTLS_PRIVATE(name) );
        while( ( ++curve_info )->MBEDTLS_PRIVATE(name) != NULL )
            mbedtls_printf( "    %s\n", curve_info->MBEDTLS_PRIVATE(name) );
    }
  #endif /* MBEDTLS_ECP_C */

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
