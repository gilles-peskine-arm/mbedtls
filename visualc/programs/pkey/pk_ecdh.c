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

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

//----------------------------------------------------------------------------
//----------------- local functions ------------------------------------------
//----------------------------------------------------------------------------
static void util_dump_prog(const void *data_in, uint32_t length, const char *prompt)
{
    const uint8_t  *data = (const uint8_t *)data_in; 
    unsigned int    i;

    if (prompt)
        fprintf( stdout, "%s: (size=%d)  ", prompt, (int)length );
    for (i = 0; i < length; ++i)
    {
        if ((i % 16 == 0) && (length > 8))
            fprintf( stdout, "\n    ");
        else if ( (i % 8) == 0)
            fprintf(stdout, "  ");
        fprintf( stdout, "%02x ", data[i] );
    }
    fprintf(stdout, "\n");
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------- Main code ------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

int main( int argc, char *argv[] )
{
    mbed_pktop_t  *pk = NULL, *pk_peer = NULL;
    char          *pwd1 = "";
    const char    *pers = "mbed_pk_ecdh";
    char          *keyfile, *keyfile_peer;
    uint8_t        buf[512];
    size_t         olen = 0;
    int            rc = 0;


    /*---------------------Code ----------------------------------------------*/
    if (argc < 3 || argc > 4)
        goto usage;

    keyfile      = argv[1];
    keyfile_peer = argv[2];
    if (argc == 4)
        pwd1 = argv[4];  // Password1 provided

    mbed_pk_init(&pk,      mbedtls_ctr_drbg_random, NULL, pers);
    mbed_pk_init(&pk_peer, mbedtls_ctr_drbg_random, NULL, pers);

    // Read the key files
    if ((rc = mbed_pk_parse_prv_keyfile( pk, keyfile, pwd1 )) != 0)
    {
        mbedtls_printf( "Reading private key from '%s' (pwd=%s) FAILED\n", keyfile, pwd1 ); fflush( stdout );
        goto fail;
    }
    if ((rc = mbed_pk_parse_pub_keyfile( pk_peer, keyfile_peer )) != 0)
    {
        mbedtls_printf( "Reading private key from '%s' FAILED\n", keyfile_peer ); fflush( stdout );
        goto fail;
    }
    mbedtls_printf("Successfully read prv  key from '%s'\n", keyfile); fflush(stdout);
    mbedtls_printf("Successfully read peer key from '%s'\n", keyfile_peer); fflush(stdout);

    if ((rc = mbed_pk_dh( pk, pk_peer, buf, sizeof(buf), &olen )) != 0)
        goto fail;
    util_dump_prog(buf, olen, "Shared Secret");

    mbedtls_printf("Done...\n\n");
    goto cleanup; 


fail:
  #if defined(MBEDTLS_ERROR_C)
    mbedtls_strerror( rc, (char *) buf, sizeof(buf) );
    mbedtls_printf( "\n  !  Last error was: %s\n\n", buf );
  #endif

usage: 
    mbedtls_printf( "usage: mbed_pk_ecdh <prv_keyfile> <peer_keyfile> [passwd]\n" );
    mbedtls_exit( rc );
  #if defined(_WIN32)
    mbedtls_printf( "\n" );
  #endif

cleanup: 
    mbed_pk_free( pk );
    mbed_pk_free( pk_peer );

  #if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
  #endif
    mbedtls_exit( rc );
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SHA256_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */

