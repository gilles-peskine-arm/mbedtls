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
//----------------------------------------------------------------------------
//----------------- Main code ------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

int main( int argc, char *argv[] )
{
    mbed_pktop_t    *pk = NULL;
    mbed_pkexport_e  level;
    mbed_pktarget_e  target;
    char             buf[32*1024];
    char            *keyfile, *pwd="";
    int              rc = 0; 


    /*---------------------Code ----------------------------------------------*/
    if (argc < 3 || argc > 4)
        goto usage;

    keyfile = argv[1];
    level   = (mbed_pkexport_e)atoi(argv[2]);  // export level provided 
    if (argc == 4) 
        pwd = argv[3]; 

    if( level <=  PK_EXPORT_DER || level >= PK_EXPORT_LAST) 
    {
        mbedtls_printf("Export level must be between %d and %d\n", PK_EXPORT_DER, PK_EXPORT_LAST); fflush( stdout );
        goto fail; 
    }

    mbed_pk_init(&pk, mbedtls_ctr_drbg_random, NULL, NULL);

    // Read the key files
    target = PK_TARGET_PRV;
    if ((rc = mbed_pk_parse_prv_keyfile( pk, keyfile, pwd )) != 0)
    {
        target = PK_TARGET_PUB;
        // Reading a private key failed, try reading a public key 
        if ((rc = mbed_pk_parse_pub_keyfile( pk, keyfile )) != 0) 
        {
            mbedtls_printf( "Reading key from '%s' FAILED\n", keyfile ); fflush( stdout );
            goto fail;
        }
    }
    mbedtls_printf("Successfully read key from '%s'\n", keyfile); fflush(stdout);
    
    if ((rc = mbed_pk_export_key_info( pk, target, level, buf, sizeof(buf))) < 0)
        goto fail;
    mbedtls_printf("\n%s\n", buf);

    mbedtls_printf("Done...\n\n");
    goto cleanup; 


    // --- Error handling --- 
fail:
  #if defined(MBEDTLS_ERROR_C)
    mbedtls_strerror( rc, (char *) buf, sizeof(buf) );
    mbedtls_printf( "\n  !  Last error was: %s\n\n", buf );
  #endif

usage: 
    mbedtls_printf( "usage: %s <keyfile> <info_level(1-3)> [pwd]\n", argv[0]);
    mbedtls_exit( rc );
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
#endif /* MBEDTLS_PK_PARSE_C && MBEDTLS_PK_WRITE_C && MBEDTLS_FS_IO &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
