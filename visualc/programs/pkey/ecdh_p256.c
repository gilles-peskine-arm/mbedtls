/*
 *  Example ECDHE with Curve25519 program
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

#include "mbedtls/ecdh.h"

#if !defined(MBEDTLS_ECDH_C) 
    #error MBEDTLS_ECDH_C
//#elif !defined(MBEDTLS_ECDH_LEGACY_CONTEXT) 
//    #error MBEDTLS_ECDH_LEGACY_CONTEXT
#elif !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) 
    #error MBEDTLS_ECP_DP_CURVE25519_ENABLED
#elif !defined(MBEDTLS_ENTROPY_C)
    #error MBEDTLS_ENTROPY_C
#elif !defined(MBEDTLS_CTR_DRBG_C)
    #error MBEDTLS_CTR_DRBG_C
#endif 

#if !defined(MBEDTLS_ECDH_C) || \
    !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_ECDH_C and/or MBEDTLS_ECDH_LEGACY_CONTEXT and/or "
                    "MBEDTLS_ECP_DP_CURVE25519_ENABLED and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
                    "not defined\n" );
    mbedtls_exit( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

#define VERBOSE 1 

#if defined(VERBOSE)
static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ )
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    mbedtls_printf( "\n" );
}

static void dump_pubkey( const char *title, mbedtls_ecdh_context_mbed *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->MBEDTLS_PRIVATE(grp), &key->MBEDTLS_PRIVATE(Q),
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

static void dump_point( const char *title, mbedtls_ecp_group *grp, mbedtls_ecp_point *point )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( grp, point, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

static void dump_mpi( const char *title, const mbedtls_mpi *MBEDTLS_PRIVATE(mpi))
{
    unsigned char buf[300];
    size_t len;

    len = mbedtls_mpi_size(MBEDTLS_PRIVATE(mpi));
    if( mbedtls_mpi_write_binary( MBEDTLS_PRIVATE(mpi), buf, len ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }
    dump_buf( title, buf, len );
}
#endif // #if defined(VERBOSE)

int dummy_entropy( void *data, unsigned char *output, size_t len )
{
    size_t i;
    (void) data;

    //use mbedtls_entropy_func to find bugs in it
    //test performance impact of entropy
    //ret = mbedtls_entropy_func(data, output, len);
    for (i=0; i<len; i++) {
        //replace result with pseudo random
        output[i] = (unsigned char) rand();
    }
    return( 0 );
}

int main( int argc, char *argv[] )
{
    int                        ret = 1;
    int                        exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdh_context       ctx_cli_main, ctx_srv_main;
    mbedtls_ecdh_context_mbed *ctx_cli, *ctx_srv;
    mbedtls_entropy_context    entropy;
    mbedtls_ctr_drbg_context   ctr_drbg;
    unsigned char              cli_to_srv[32], srv_to_cli[32];
    const char                 pers[] = "ecdh";
    ((void) argc);
    ((void) argv);

    mbedtls_ecdh_init( &ctx_cli_main );
    mbedtls_ecdh_init( &ctx_srv_main );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    ctx_cli = &ctx_cli_main.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh);
    ctx_srv = &ctx_srv_main.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh);

    /*
     * Initialize random number generation
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, dummy_entropy, &entropy,
                               (const unsigned char *) pers,
                               sizeof pers ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Client: initialize context and generate keypair
     */
    mbedtls_printf( "  . Setting up client context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_cli->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &ctx_cli->MBEDTLS_PRIVATE(grp), &ctx_cli->MBEDTLS_PRIVATE(d), &ctx_cli->MBEDTLS_PRIVATE(Q),
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_cli->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), cli_to_srv, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );
    dump_pubkey( "Server Public key: ", ctx_cli);
    dump_point(  "Server Pubkey pnt: ", &ctx_cli->MBEDTLS_PRIVATE(grp), &ctx_cli->MBEDTLS_PRIVATE(Q)) ;
    dump_buf( "Server Pub key X : ", cli_to_srv, 32);

    /*
     * Server: initialize context and generate keypair
     */
    mbedtls_printf( "  . Setting up server context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_srv->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &ctx_srv->MBEDTLS_PRIVATE(grp), &ctx_srv->MBEDTLS_PRIVATE(d), &ctx_srv->MBEDTLS_PRIVATE(Q),
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_srv->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), srv_to_cli, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );
    dump_pubkey( "Server Public key: ", ctx_srv);
    dump_point(  "Server Pubkey pnt: ", &ctx_srv->MBEDTLS_PRIVATE(grp), &ctx_srv->MBEDTLS_PRIVATE(Q)) ;
    dump_buf( "Server Pub key X : ", srv_to_cli, 32);

    /*
     * Server: read peer's key and generate shared secret
     */
    mbedtls_printf( "  . Server reading client key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_srv->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(Z), 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }
    //ret = mbedtls_mpi_read_binary( &ctx_srv->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(X), cli_to_srv, 32 );
    //if( ret != 0 )
   // {
   //     mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
   //     goto exit;
   // }

    mbedtls_ecp_copy( &ctx_srv->MBEDTLS_PRIVATE(Qp), &ctx_cli->MBEDTLS_PRIVATE(Q)); 

    ret = mbedtls_ecdh_compute_shared( &ctx_srv->MBEDTLS_PRIVATE(grp), &ctx_srv->MBEDTLS_PRIVATE(z),
                                       &ctx_srv->MBEDTLS_PRIVATE(Qp), &ctx_srv->MBEDTLS_PRIVATE(d),
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );
    dump_mpi( "Server shared secret: ", &ctx_srv->MBEDTLS_PRIVATE(z));

    /*
     * Client: read peer's key and generate shared secret
     */
    mbedtls_printf( "  . Client reading server key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_cli->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(Z), 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    //ret = mbedtls_mpi_read_binary( &ctx_cli->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(X), srv_to_cli, 32 );
    //if( ret != 0 )
   // {
    //    mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
    //    goto exit;
    //}
    mbedtls_ecp_copy( &ctx_cli->MBEDTLS_PRIVATE(Qp), &ctx_srv->MBEDTLS_PRIVATE(Q)); 

    ret = mbedtls_ecdh_compute_shared( &ctx_cli->MBEDTLS_PRIVATE(grp), &ctx_cli->MBEDTLS_PRIVATE(z),
                                       &ctx_cli->MBEDTLS_PRIVATE(Qp), &ctx_cli->MBEDTLS_PRIVATE(d),
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );
    dump_mpi( "Client shared secret: ", &ctx_srv->MBEDTLS_PRIVATE(z));

    /*
     * Verification: are the computed secrets equal?
     */
    mbedtls_printf( "  . Checking if both computed secrets are equal..." );
    fflush( stdout );

    ret = mbedtls_mpi_cmp_mpi( &ctx_cli->MBEDTLS_PRIVATE(z), &ctx_srv->MBEDTLS_PRIVATE(z) );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ecdh_free( &ctx_srv_main );
    mbedtls_ecdh_free( &ctx_cli_main );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    mbedtls_exit( exit_code );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_CURVE25519_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
