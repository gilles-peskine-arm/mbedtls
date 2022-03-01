
#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) ||         \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) ||  \
    !defined(MBEDTLS_CTR_DRBG_C) || defined(MBEDTLS_X509_REMOVE_INFO)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined and/or MBEDTLS_X509_REMOVE_INFO defined.\n");
    mbedtls_exit( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DFL_FILENAME            "cert.crt"

// global options
const char *filename;       /* filename of the certificate file     */

#if 0 
static void util_dump(const void *data_in, uint32_t length, const char *prompt)
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

#endif 

int main( int argc, char *argv[] )
{
    mbedtls_x509_crt  cert;
    unsigned char     buf[2048];
    int               rc = 1;
    int               i;
    char              *p, *q; // *keyfile = NULL;
    
    /*---------------------Code ----------------------------------------------*/
    // Set to sane values
    mbedtls_x509_crt_init( &cert );
    if( argc == 0 )
        goto usage;
    
    filename = DFL_FILENAME;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "certname" ) == 0 )
            filename = q;
        //else if( strcmp( p, "keyfile" ) == 0 )
        //    keyfile = q;
        else
            goto usage;
    }

    // 1.1. Load the trusted CA
    mbedtls_printf( "  . Loading the certificate ..." ); fflush( stdout ); 
    if( ( rc = mbedtls_x509_crt_parse_file( &cert, filename ) ) < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_path(%s) returned -0x%x\n\n", filename, (unsigned int) -rc );
        goto fail;
    }
    mbedtls_printf( "ok\n");

    mbedtls_printf( "  . Certificate info ..." ); fflush( stdout ); 
    if( (rc = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &cert )) < 0) 
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", rc );
        goto fail;
    }
  #if 0 
    if ( keyfile != NULL) // Check the signature
    {
        pktop_t pktop; 
        if (( rc = mbed_pk_parse_prv_keyfile(pktop, keyfile, "")) != 0) 
            goto fail; 
    }
  #endif 
    
    mbedtls_printf( "\n%s\n", buf );
    mbedtls_printf( "\ndone...\n");
    rc = MBEDTLS_EXIT_SUCCESS;
    goto cleanup; 


fail:
   rc = MBEDTLS_EXIT_FAILURE;
usage:
    mbedtls_printf("\n usage: cert_info param=<>...\n");
    mbedtls_printf("\n acceptable parameters:\n");
    mbedtls_printf("    certname=%%s         default: cert.crt\n");
    mbedtls_printf("    keyfile=%%s          default: no key\n");
cleanup: 
    mbedtls_x509_crt_free( &cert );
  #if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to fail this program.\n" );
    fflush( stdout ); getchar();
  #endif
    mbedtls_exit( rc);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
