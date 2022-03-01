#include "common.h"

#ifdef KEM_REWORK

#if defined(MBEDTLS_SSL_CLI_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <string.h>
#include <stdint.h>

#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#include "mbedtls/platform_util.h"
#endif

#include "ssl_misc.h"



//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------

#define LOGD printf   // TODO 
#define KEM_SHARED_BLOCK_SIZE   32 
#define KEM_PREMASTER_SIZE     (KEM_SHARED_BLOCK_SIZE * 3)

#ifndef TRUE 
  #define TRUE  1 
  #define FALSE 0
#endif 

//----------------------------------------------------------------------------
//----------------- Type defines ---------------------------------------------
//----------------------------------------------------------------------------
// Shorten commonly used names 
typedef mbedtls_ssl_handshake_params     ssl_handshake_t;
typedef mbedtls_ssl_context              sslctx_t; 
typedef ssl_kemctx_t                     kemctx_t; 
typedef const mbedtls_ssl_ciphersuite_t  ciphersuite_t; 
typedef mbed_hybpk_t                    pktype_e; 

// typedef uint32_t   mbed_hybpk_t;

typedef enum 
{
    KEM_STEP1 = 1, 
    KEM_STEP2,
    KEM_STEP3,
    KEM_STEP4
} kem_state_e; 



//----------------------------------------------------------------------------
//----------------- Prototypes -----------------------------------------------
//----------------------------------------------------------------------------
int ssl_parse_signature_algorithm( mbedtls_ssl_context *ssl, uint8_t **p, uint8_t *end, mbed_md_alg_e *md_alg, mbed_hybpk_t *pk_alg );
int ssl_conf_has_static_psk( mbedtls_ssl_config const *conf ); 
int ssl_parse_client_psk_identity( mbedtls_ssl_context *ssl, unsigned char **p, const unsigned char *end ); 

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Local Functions ------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
 * Description: Chech if the KEM uses ephemeral keys  
 *
 * Arguments:   suite_info  - pointer to the cipher suite 
 * 
 * result:      TRUE/FALSE  
 *****************************************************************************/
static int ssl_ciphersuite_uses_eph_kem_key( ciphersuite_t *suite_info )
{
    return !mbedtls_ssl_ciphersuite_no_pfs(suite_info); 
}


/******************************************************************************
 * Description: Chech if the KEM uses Preshared keys 
 *
 * Arguments:   suite_info  - pointer to the cipher suite 
 * 
 * result:      TRUE/FALSE  
 *****************************************************************************/
int ssl_get_ciphersuite_psk(ciphersuite_t *suite_info )
{
    switch( suite_info->key_exchange )
    {
        case MBEDTLS_KEM_PSK:
        case MBEDTLS_KEM_RSA_PSK:
        case MBEDTLS_KEM_DHE_PSK:
        case MBEDTLS_KEM_ECDHE_PSK:
            return TRUE; 
        default:
            return FALSE;
    }
}

/******************************************************************************
 * Description: Get the peer key context  
 *
 * Arguments:   ssl      - ssl context
 *              peerkey  - address of the peer key 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int ssl_get_peerkey_ctx( sslctx_t *ssl, mbed_pktop_t **peer_pk ) 
{
  #if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    *peer_pk = ssl->handshake->kem_ctx.peer_pubkey;
  #else 
    if( ssl->session_negotiate->peer_cert == NULL )
    {
        /* Should never happen */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    *peer_pk = ssl->session_negotiate->peer_cert->pktop;
  #endif 
    return 0; 
}


/*----------------------------------------------------------------------------*
 *----------------- DH functions ----------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
 * Description: Add an (ephemeral) RSA key to the key top context  
 *
 * Arguments:   kem_ctx - kem context
 *              ssl     - ssl context (for curve info ) 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int ssl_dh_addkey( mbed_pktop_t *pk, sslctx_t *ssl)
{
    (void) pk;
    (void) ssl;

    LOGD("%s() This function is not supported yet\n", __func__); 
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR; 
}


/*----------------------------------------------------------------------------*
 *----------------- EC functions ---------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
 * Description: Add an (ephemeral) EC key to the key top context  
 *
 * Arguments:   kem_ctx - kem context
 *              ssl     - ssl context (for curve info ) 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int ssl_ec_addkey(mbed_pktop_t *pk, kemctx_t *kem_ctx, sslctx_t *ssl, kem_state_e kem_state)
{      
    const mbedtls_ecp_curve_info  **curve = NULL, *peer_curve;
    const mbedtls_ecp_group_id     *gid;
    char                            params[48]; 
    mbedtls_ecp_group_id            grp_id;
    int                             rc, cnt = 0;


    /*---------------------Code ----------------------------------------------*/
    printf("%s():\n", __func__);
    // --- Match our preference list against the offered curves
    if ( kem_state == KEM_STEP1)
    {
        for (gid = ssl->conf->curve_list; *gid != MBEDTLS_ECP_DP_NONE; gid++)
        {
            for( curve = ssl->handshake->curves; *curve != NULL; curve++ )
                printf("%s(): curve %d with id = %d gid=%d\n",__func__, ++cnt,  (int)(*curve)->grp_id, (int)*gid);

            for( curve = ssl->handshake->curves; *curve != NULL; curve++ )
                if( (*curve)->grp_id == *gid )
                    goto curve_matching_done;
        }
curve_matching_done:
        if( curve == NULL || *curve == NULL )
            goto fail_curve_match; 
        peer_curve = *curve;
    }
    else  // STEP3 
    {
        // Get the curve info from the KEM peer key 
        if (  kem_ctx->kem_peerkey == NULL)
            goto fail_curve_match; 
        if ((rc = mbed_pk_get_ec_grpid( kem_ctx->kem_peerkey, 0, &grp_id )) != 0)  // TODO fix this
            goto fail_curve_match; 
        if( ( peer_curve = mbedtls_ecp_curve_info_from_grp_id( grp_id )) == NULL)
            goto fail_curve_match;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDHE curve: %s", peer_curve->name ) );

    // --- generate a key with that curve 
    snprintf(params, sizeof(params),"curve=%s", peer_curve->name ); 
    if( (rc = mbed_pk_keygen( pk, MBEDTLS_PK_ECKEY_DH, params)) != 0) 
        goto fail; 

    return 0; 

    // --- Error handling --- 
fail_curve_match: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching curve for ECDHE" ) );
    rc = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/*----------------------------------------------------------------------------*
 *----------------- Kyber functions ---------------------------------------------*
 *----------------------------------------------------------------------------*/

/******************************************************************************
 * Description: Add an (ephemeral) RSA key to the key top context  
 *
 * Arguments:   kem_ctx - kem context
 *              ssl     - ssl context (for curve info ) 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int ssl_kyber_addkey( mbed_pktop_t *pk, sslctx_t *ssl)
{
    int rc; 
    (void) pk;
    (void) ssl;

    /*---------------------Code ----------------------------------------------*/
    // --- TODO: select the kyber algorithm with the correct NIST security level 
    if( (rc = mbed_pk_keygen( pk, MBEDTLS_PK_KYBER, "")) != 0) 
        goto fail; 
    return rc; 

    // --- Error handling --- 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}



/******************************************************************************
 * Description: Add an (ephemeral) RSA key to the key top context  
 *
 * Arguments:   kem_ctx - kem context
 *              ssl     - ssl context (for curve info ) 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int ssl_rsa_addkey( mbed_pktop_t *pk)
{
    int rc; 

    // For test purposes only, always create the RSA2048 key. 
    if( (rc = mbed_pk_keygen( pk, MBEDTLS_PK_RSA, (char*)"size=2048")) != 0)     
    {
        LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    }
    return rc; 
}


/******************************************************************************
 * Description: Generate the (ephemeral) key needed for the key exchange. 
 *              For DH algorithms keys need to be generated in KEM step1 and step3
 *
 * Arguments:   kem_ctx      - kem context
 *              ssl          - ssl context (for curve info )
 *              process_step - step in the KEM process 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int ssl_kem_genkey_eph( kemctx_t *kem_ctx, sslctx_t *ssl, kem_state_e kem_state) 
{
    mbed_hybpk_t   hybpk_alg = kem_ctx->hybpk_alg;
    pktype_e       pktype = 0; 
    int            rc; 
    
    /*---------------------Code ----------------------------------------------*/
    if (kem_ctx->kem_key != NULL)
        goto fail_internal_error;

    if ((rc = mbed_pk_init( &kem_ctx->kem_key, NULL, NULL, NULL )) != 0)
        goto fail;    
    
    // Generate the ephemeral key  
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "Generate KEM keys hybpk_alg = 0x%x", (unsigned)hybpk_alg));
    while ( (pktype =(pktype_e)(hybpk_alg & 0xff)) != MBEDTLS_PK_NONE) 
    {
        hybpk_alg = (hybpk_alg>>8); 

        // TODO: The following should be a replaced with a generic key generate function based on NIST levels 
        switch (pktype)
        {
            case MBEDTLS_PK_ECKEY_DH: 
            case MBEDTLS_PK_ECKEY:   rc = ssl_ec_addkey ( kem_ctx->kem_key, kem_ctx, ssl, kem_state);  break;  
            case MBEDTLS_PK_DH:      rc = ssl_dh_addkey ( kem_ctx->kem_key, ssl);  break; 

            // --- Following algorithms are not Diffie Hellman keys, Uses encap/decap to transfer the secret message 
            // --- So only need to generate a key at KEM process step1 
            case MBEDTLS_PK_KYBER:   
                if( kem_state == KEM_STEP1)  
                    rc = ssl_kyber_addkey ( kem_ctx->kem_key, ssl);  
                break; 
            case MBEDTLS_PK_RSA:   
                if( kem_state == KEM_STEP1)  
                    rc = ssl_rsa_addkey( kem_ctx->kem_key);       
                break; 
            default:
                goto fail_pktype; 
        }
    }
    if ( rc != 0) 
        goto fail;
    return rc; 

    // --- Error handling --- 
fail_internal_error:
    rc = MBEDTLS_ERR_SSL_INTERNAL_ERROR;   goto fail; 
fail_pktype: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;  
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); fflush(stdout);
    kem_ctx->kem_key = mbed_pk_free( kem_ctx->kem_key );  // cleanup
    return rc; 
}


/******************************************************************************
 * Description: Prepare the ServerKeyExchange message, up to and including
 *              calculating the signature if any, but excluding formatting the
 *              signature and sending the message.
 *  
 * Arguments:   ssl           -  ssl context pointer 
 *              singature_len - container for the resulting signature length
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int ssl_prepare_server_key_exchange( mbedtls_ssl_context *ssl, size_t *signature_len )
{
    ciphersuite_t  *suite_info = ssl->handshake->ciphersuite_info;
    kemctx_t       *kem_ctx = &ssl->handshake->kem_ctx;
    mbed_pktop_t   *own_pk; 
    int             rc; 

  #if defined(MBEDTLS_KEM_SOME_PFS_ENABLED) &&  defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED)
    uint8_t *dig_signed = NULL;
  #endif  
    (void) suite_info; /* unused in some configurations */
  #if !defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED)
    (void) signature_len;
  #endif 
#if defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED) 
  #if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t out_buf_len = ssl->out_buf_len - ( ssl->out_msg - ssl->out_buf );
  #else
    size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN - ( ssl->out_msg - ssl->out_buf );
  #endif
#endif

    /*---------------------Code ----------------------------------------------*/
    ssl->out_msglen = 4; /* header (type:1, length:3) to be written later */

    // --- Part 1: Provide key exchange parameters for chosen ciphersuite.

  #if defined(MBEDTLS_KEM_DHE_PSK_ENABLED)   || defined(MBEDTLS_KEM_ECDHE_PSK_ENABLED)
    // ---
    // For (EC)DHE key exchanges with PSK, parameters are prefixed by support
    // identity hint (RFC 4279, Sec. 3). Until someone needs this feature,
    //  we use empty support identity hints here.
    // --- 
    if( suite_info->key_exchange == MBEDTLS_KEM_DHE_PSK || suite_info->key_exchange == MBEDTLS_KEM_ECDHE_PSK )
    {
        ssl->out_msg[ssl->out_msglen++] = 0x00;
        ssl->out_msg[ssl->out_msglen++] = 0x00;
    }
  #endif 

    // TODO switch this 
    if ( ssl_ciphersuite_uses_eph_kem_key( suite_info ) ) // Ciphersuite uses ephemeral keys 
    {
        uint8_t *p = ssl->out_msg + ssl->out_msglen; 
        size_t   size = MBEDTLS_SSL_OUT_CONTENT_LEN - ssl->out_msglen;                  
        size_t   len;
        
        kem_ctx->hybpk_alg = mbedtls_ssl_get_ciphersuite_kem_pk_alg(suite_info); 

        if( (rc = ssl_kem_genkey_eph( kem_ctx, ssl, KEM_STEP1)) != 0) 
            goto fail; 

        // write the public key
        if ((rc = mbed_pk_write_pubkey_ssl(kem_ctx->kem_key, p, size, &len)) != 0)
            goto fail; 
        

      #if defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED)
        dig_signed = ssl->out_msg + ssl->out_msglen;
      #endif
        ssl->out_msglen += len;

        // Dump the public key data
        MBEDTLS_SSL_DEBUG_BUF( 3, "Server ephemeral public key", p, len ); 
    }


     // --- Part 2: For key exchanges involving the server signing the
     //             exchange parameters, compute and add the signature here.    
  #if defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED)
    if( mbedtls_ssl_ciphersuite_uses_server_signature( suite_info ) )
    {
        mbed_md_alg_e  md_alg;
        size_t         dig_signed_len = ssl->out_msg + ssl->out_msglen - dig_signed;
        size_t         hashlen = 0;
        uint8_t  hash[MBEDTLS_MD_MAX_SIZE];
        int            rc = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        // --- 2.1: Choose hash algorithm:

    #if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        // --- For TLS 1.2, obey signature-hash-algorithm extension to choose appropriate hash.
        mbed_hybpk_t sig_alg = mbedtls_ssl_get_ciphersuite_sig_pk_alg( suite_info );
        
        if( ssl->minor_ver != MBEDTLS_SSL_MINOR_VERSION_3 )
            goto fail_internal_error;

         // --- For TLS 1.2, obey signature-hash-algorithm extension (RFC 5246, Sec. 7.4.1.4.1). 
        if( sig_alg == MBEDTLS_PK_NONE ||
            ( md_alg = mbedtls_ssl_sig_hash_set_find( &ssl->handshake->hash_algs, sig_alg ) ) == MBEDTLS_MD_NONE )
        {
            // ... because we choose a cipher suite only if there is a matching hash.
            goto fail_internal_error;
        }
    #endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "pick hash algorithm %u for signing", (unsigned) md_alg ) );

        // --- 2.2: Compute the hash to be signed
    #if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( md_alg != MBEDTLS_MD_NONE )
        {
            MBEDTLS_SSL_DEBUG_BUF( 3, "parameters data digital signed ", dig_signed, dig_signed_len );
            rc = mbedtls_ssl_get_key_exchange_md_tls1_2( ssl, hash, &hashlen, dig_signed, dig_signed_len, md_alg );
            if( rc != 0 )
                goto fail;
        }
        else
    #endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
        {
            goto fail_internal_error;
        }

        MBEDTLS_SSL_DEBUG_BUF( 3, "parameters hash", hash, hashlen );

        // --- 2.3: Compute and add the signature
    #if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
        {
            /*
             * For TLS 1.2, we need to specify signature and hash algorithm
             * explicitly through a prefix to the signature.
             *
             * struct {
             *    HashAlgorithm hash;
             *    SignatureAlgorithm signature;
             * } SignatureAndHashAlgorithm;
             *
             * struct {
             *    SignatureAndHashAlgorithm algorithm;
             *    opaque signature<0..2^16-1>;
             * } DigitallySigned;
             *
             */
            ssl->out_msg[ssl->out_msglen++] = mbedtls_ssl_hash_from_md_alg( md_alg );
            ssl->out_msg[ssl->out_msglen++] = mbedtls_ssl_sig_from_pk_alg( sig_alg );
        }
    #endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    #if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
        if( ssl->conf->f_async_sign_start != NULL )
        {
            rc = ssl->conf->f_async_sign_start( ssl, mbedtls_ssl_own_cert( ssl ), md_alg, hash, hashlen );
            switch( rc )
            {
            case MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH:
                /* act as if f_async_sign was null */
                break;
            case 0:
                ssl->handshake->async_in_progress = 1;
                return( ssl_resume_server_key_exchange( ssl, signature_len ) );
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
                ssl->handshake->async_in_progress = 1;
                return( MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS );
            default:
                MBEDTLS_SSL_DEBUG_RET( 1, "f_async_sign_start", rc );
                return( rc );
            }
        }
    #endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

        if( (own_pk =  mbedtls_ssl_own_key( ssl ))  == NULL )
            goto fail_no_prvkey; 

        // --- Append the signature to ssl->out_msg, leaving 2 bytes for the signature length 
        // --- which will be added in ssl_write_server_key_exchange after the call to 
        // --- ssl_prepare_server_key_exchange. ssl_write_server_key_exchange also takes care 
        // --- of incrementing ssl->out_msglen. 
        if( ( rc = mbed_pk_sign(own_pk, md_alg, hash, hashlen, ssl->out_msg + ssl->out_msglen + 2,
                                out_buf_len - ssl->out_msglen - 2, signature_len) ) != 0 )
        {
            goto fail_sign; 
        }
    }
  #endif /* MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED */
    return( 0 );


    // --- Error handling --- 
fail_sign: 
    MBEDTLS_SSL_DEBUG_RET( 1, "mbed_pk_sign", rc ); goto fail;
fail_no_prvkey: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no private key" ) );
    rc = MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED; goto fail;
fail_internal_error: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    rc =  MBEDTLS_ERR_SSL_INTERNAL_ERROR;
fail: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_prepare_server_key_exchange() failed" ) );
    return rc; 
}


#if defined(MBEDTLS_KEM_RSA_ENABLED) || defined(MBEDTLS_KEM_RSA_PSK_ENABLED)
/******************************************************************************
 * Description: Generate a pre-master secret and encrypt it with the server's RSA key 
 *
 * Arguments:   kem_ctx      - kem context
 *              ssl          - ssl context (for curve info )
 *              process_step - step in the KEM process 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int ssl_write_encrypted_pms( mbedtls_ssl_context *ssl, size_t offset, size_t *olen, size_t pms_offset )
{
    int rc = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len_bytes = 2;
    uint8_t *p = ssl->handshake->premaster + pms_offset;
    mbed_pktop_t * peer_pk;

    if( offset + len_bytes > MBEDTLS_SSL_OUT_CONTENT_LEN )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small for encrypted pms" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }
    /*
     * Generate (part of) the pre-master as
     *  struct {
     *      ProtocolVersion client_version;
     *      opaque random[46];
     *  } PreMasterSecret;
     */
    mbedtls_ssl_write_version( ssl->conf->max_major_ver, ssl->conf->max_minor_ver, ssl->conf->transport, p );

    if( ( rc = ssl->conf->f_rng( ssl->conf->p_rng, p + 2, 46 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_rng", rc );
        return( rc );
    }

    ssl->handshake->kem_ctx.pms_len = 48;

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    peer_pk = &ssl->handshake->peer_pubkey;
#else /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    if( ssl->session_negotiate->peer_cert == NULL )
    {
        /* Should never happen */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    peer_pk = &ssl->session_negotiate->peer_cert->pktop;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

    /*
     * Now write it out, encrypted
     */
    if( ! mbed_pk_can_do( peer_pk, MBEDTLS_PK_RSA ) )
    {
        // TODO
        printf("%s(): WARNING: unsupported RSA only use of mbed_pk_can_do() !!!!!\n"); fflush(stdout); 
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "certificate key type mismatch" ) );
        return( MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH );
    }

    if( ( rc = mbed_pk_encap( peer_pk,
                            p, ssl->handshake->kem_ctx.pms_len,
                            ssl->out_msg + offset + len_bytes, olen,
                            MBEDTLS_SSL_OUT_CONTENT_LEN - offset - len_bytes,
                            ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_rsa_pkcs1_encrypt", rc );
        return( rc );
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( len_bytes == 2 )
    {
        ssl->out_msg[offset+0] = (uint8_t)( *olen >> 8 );
        ssl->out_msg[offset+1] = (uint8_t)( *olen      );
        *olen += 2;
    }
#endif

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    /* We don't need the peer's public key anymore. Free it. */
    mbed_pk_free( peer_pk );
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    return( 0 );
}
#endif // MBEDTLS_KEM_RSA_ENABLED || MBEDTLS_KEM_RSA_PSK_ENABLED 



static int ssl_parse_server_psk_hint( mbedtls_ssl_context *ssl, uint8_t **p, uint8_t *end )
{
    int rc = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    uint16_t  len;
    ((void) ssl);

    /*
     * PSK parameters:
     *
     * opaque psk_identity_hint<0..2^16-1>;
     */
    if( end - (*p) < 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "bad server key exchange message (psk_identity_hint length)" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }
    len = (*p)[0] << 8 | (*p)[1];
    *p += 2;

    if( end - (*p) < len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "bad server key exchange message (psk_identity_hint length)" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /*
     * Note: we currently ignore the PKS identity hint, as we only allow one
     * PSK to be provisionned on the client. This could be changed later if
     * someone needs that feature.
     */
    *p += len;
    rc = 0;

    return( rc );
}


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Global Functions ----------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
 * Description: Create the TLS client key exchange message (Step 1 in KEM process)
 *              For ciphersuites that do not include a ServerKeyExchange message,
 *              do nothing. Either way, move on to the next step in the SSL state
 *               machine.
 *              Step 1 : write_server_key_exchange (created by server)  
 *              Step 2 : parse_server_key_exchange (parsed by client)  
 *              Step 3 : write_client_key_exchange (created by client)  
 *              Step 4 : parse_client_key_exchange (parsed by server)
 *              After step 4 client and server have the same shared secret (premaster) 
 *
 * Arguments:   ssl -  ssl context pointer
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int ssl_pkwrap_write_server_key_exchange( sslctx_t  *ssl )
{
  #if defined(MBEDTLS_KEM_SOME_NON_PFS_ENABLED)
    ciphersuite_t  *suite_info = ssl->handshake->ciphersuite_info;
  #endif 
    int             rc = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t          signature_len = 0;


    /*---------------------Code ----------------------------------------------*/
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write server key exchange" ) );

  #if defined(MBEDTLS_KEM_SOME_NON_PFS_ENABLED)
    // --- Extract static ECDH parameters and abort if ServerKeyExchange is not needed.
    if( ssl_ciphersuite_uses_eph_kem_key( suite_info ) == FALSE)
    {
        /* For suites involving ECDH, extract DH parameters
         * from certificate at this point. */
      #if defined(MBEDTLS_KEM_SOME_ECDH_ENABLED)
        if( mbedtls_ssl_ciphersuite_uses_ecdh( suite_info ) )
        {
            // TODO this should not be needed 
            ssl_get_ecdh_params_from_cert( ssl );
        }
      #endif 

        /* Key exchanges not involving ephemeral keys don't use
         * ServerKeyExchange, so end here. */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write server key exchange" ) );
        goto finish; 
    }
  #endif /* MBEDTLS_KEM_SOME_NON_PFS_ENABLED */

  #if defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED) &&  defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    /* If we have already prepared the message and there is an ongoing
     * signature operation, resume signing. */
    if( ssl->handshake->async_in_progress != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "resuming signature operation" ) );
        rc = ssl_resume_server_key_exchange( ssl, &signature_len );
        if( rc == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ) 
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write server key exchange (pending)" ) );
            goto fail_async;  // preserve ssl->out_msglen in ASYNC case 
        }
    }
    else
  #endif 
    {
        // --- ServerKeyExchange is needed. Prepare the message. 
        rc = ssl_prepare_server_key_exchange( (mbedtls_ssl_context*)ssl, &signature_len );
    }
    if( rc != 0 )
        goto fail; 

    /* If there is a signature, write its length.
     * ssl_prepare_server_key_exchange already wrote the signature
     * itself at its proper place in the output buffer. */
  #if defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED)
    if( signature_len != 0 )
    {
        ssl->out_msg[ssl->out_msglen++] = (uint8_t)( signature_len >> 8 );
        ssl->out_msg[ssl->out_msglen++] = (uint8_t)( signature_len      );

        MBEDTLS_SSL_DEBUG_BUF( 3, "my signature", ssl->out_msg + ssl->out_msglen, signature_len ); 

        /* Skip over the already-written signature */
        ssl->out_msglen += signature_len;
    }
  #endif /* MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED */

    // --- Add header and send. 
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE;

    if( ( rc = mbedtls_ssl_write_handshake_msg( ssl ) ) != 0 )
        goto fail_handshake_msg; 

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write server key exchange" ) );

finish: 
    ssl->state++;
    return  0;

    // --- Error handling --- 
fail_handshake_msg: 
    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_handshake_msg", rc );
    rc = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE; 
fail: 
    ssl->out_msglen = 0;
    return( rc );
}


/******************************************************************************
 * Description: Parse the TLS server key exchange message (Step 2 in KEM process)   
 *              Step 1 : write_server_key_exchange (created by server)  
 *              Step 2 : parse_server_key_exchange (parsed by client)  
 *              Step 3 : write_client_key_exchange (created by client)  
 *              Step 4 : parse_client_key_exchange (parsed by server)
 *              After step 4 client and server have the same shared secret (premaster) 
 *
 * Arguments:   ssl -  ssl context pointer
 * 
 * result:      TRUE/FALSE  
 *****************************************************************************/
int ssl_pkwrap_parse_server_key_exchange( sslctx_t *ssl )
{
    ssl_handshake_t   *handshake = ssl->handshake;
    kemctx_t          *kem_ctx = &handshake->kem_ctx;
    ciphersuite_t     *suite_info = handshake->ciphersuite_info;
    uint8_t           *p, *end; 
    int                rc;

    /*---------------------Code ----------------------------------------------*/
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse server key exchange" ) );
    
  #if defined(MBEDTLS_KEM_RSA_ENABLED)
    // TODO remove this section 
    if( suite_info->key_exchange == MBEDTLS_KEM_RSA )
        goto finish_skip_key_exchange;
  #endif
  #if defined(MBEDTLS_KEM_ECDH_RSA_ENABLED) || defined(MBEDTLS_KEM_ECDH_ECDSA_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_ECDH_RSA || suite_info->key_exchange == MBEDTLS_KEM_ECDH_ECDSA )
        goto finish_skip_key_exchange;     // No ephemeral key => no key exchange 
  #endif 

    // Read the server key exchange record 
    if( ( rc = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
        goto fail_read_record;

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
        goto fail_unexpected_message;
   
    // ServerKeyExchange may be skipped with PSK and RSA-PSK when the server
    // doesn't use a psk_identity_hint
    if( ssl->in_msg[0] != MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE )
    {
        if( suite_info->key_exchange == MBEDTLS_KEM_PSK || suite_info->key_exchange == MBEDTLS_KEM_RSA_PSK )
        {
            // Current message is probably either CertificateRequest or ServerHelloDone 
            ssl->keep_current_message = 1;
            goto finish;
        }
        goto fail_unexpected_message; 
    }

    p   = ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl );
    end = ssl->in_msg + ssl->in_hslen;
    // MBEDTLS_SSL_DEBUG_BUF( 3,   "server key exchange", p, end - p );

#if defined(MBEDTLS_KEM_SOME_PSK_ENABLED)
    if( ssl_get_ciphersuite_psk(suite_info) )
    {
        if( ssl_parse_server_psk_hint( ssl, &p, end ) != 0 )
            goto fail_decode_error; 
    }  
#endif  //  MBEDTLS_KEM_SOME_PSK_ENABLED  

  #if defined(MBEDTLS_KEM_PSK_ENABLED) ||  defined(MBEDTLS_KEM_RSA_PSK_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_PSK || suite_info->key_exchange == MBEDTLS_KEM_RSA_PSK )
        goto finish;  // nothing more to do  
    else
  #endif 
#if defined(MBEDTLS_KEM_ECJPAKE_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_ECJPAKE )
    {
        rc = mbedtls_ecjpake_read_round_two( &ssl->handshake->ecjpake_ctx, p, end - p );
        if( rc != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecjpake_read_round_two", rc );
            mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE );
            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        }
    }
    else
#endif /* MBEDTLS_KEM_ECJPAKE_ENABLED */
#if defined(MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED)
    if( ssl_ciphersuite_uses_eph_kem_key( suite_info ) == TRUE )
    {
        mbed_md_alg_e      md_alg = MBEDTLS_MD_NONE;
        mbed_hybpk_t       suite_sig_hyb_pktype, sig_hybpk_alg = MBEDTLS_PK_NONE; 
        mbed_pktop_t      *peer_pk; 
        uint8_t           *params = ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl );
        uint8_t           *saved_p, hash[64];
        size_t             sig_len, hashlen; 
        size_t             params_len = p - params;
        void              *rs_ctx = NULL;
        

        kem_ctx->hybpk_alg = mbedtls_ssl_get_ciphersuite_kem_pk_alg(suite_info); 

        MBEDTLS_SSL_DEBUG_RET(3,"KEM STEP2: hybpk_alg", kem_ctx->hybpk_alg); 
        // --- The server key exchanged should contain a public following by a signature
        // --- Load the public key 
        if ( (rc = mbed_pk_init( &kem_ctx->kem_peerkey, NULL, NULL, NULL)) != 0)  // TODO use SSL RNG 
            goto fail; 

        saved_p = p;
        if ( (rc = mbed_pk_parse_pubkey_ssl( kem_ctx->kem_peerkey, PK_TARGET_PUBSSL, kem_ctx->hybpk_alg, &p, end)) != 0) 
            goto fail; 
        params_len += (size_t)(p-saved_p);

        // --- Handle the digitally-signed structure
    #if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
        {
            suite_sig_hyb_pktype = mbedtls_ssl_get_ciphersuite_sig_pk_alg( suite_info );

            if( ssl_parse_signature_algorithm( ssl, &p, end, &md_alg, &sig_hybpk_alg ) != 0 )
                goto fail_illegal_parameter;

            if( sig_hybpk_alg != suite_sig_hyb_pktype)
            {
                MBEDTLS_SSL_DEBUG_MSG(1, ("hybpk_alg mismatch: sig_hybpk_alg=0x%x, expected from suite = 0x%x\n", 
                                          (unsigned)sig_hybpk_alg, (unsigned)suite_sig_hyb_pktype) );
                goto fail_illegal_parameter;
            }
        }
        else
    #endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
        {
            goto fail_internal_error; // should never happen 
        }
        
        // --- Read signature
        if( p > end - 2 )
            goto fail_decode_error; 
        sig_len = ( p[0] << 8 ) | p[1];
        p += 2;

        if( p != end - sig_len )
            goto fail_decode_error; 

        // --- Compute the hash that has been signed
    #if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( md_alg != MBEDTLS_MD_NONE )
        {
            MBEDTLS_SSL_DEBUG_BUF( 3, "parameters data this data is signed", params, params_len );
            if( ( rc = mbedtls_ssl_get_key_exchange_md_tls1_2( ssl, hash, &hashlen, params, params_len, md_alg )) != 0)
                goto fail; 
        }
        else
    #endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
        {
            goto fail_internal_error; // should never happen 
        }
        if( (rc = ssl_get_peerkey_ctx(ssl, &peer_pk)) != 0) 
            goto fail; 
      
        //  --- Verify the signature
        if( !mbed_pk_can_do( peer_pk, sig_hybpk_alg ) )
            goto fail_type_mismatch;

        MBEDTLS_SSL_DEBUG_BUF( 3, "Signature", p, sig_len );
        
        if( ( rc = mbed_pk_verify_restartable( peer_pk, md_alg, hash, hashlen, p, sig_len, rs_ctx ) ) != 0 )
            goto fail_decrypt_error;

    #if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        /* We don't need the peer's public key anymore. Free it,
         * so that more RAM is available for upcoming expensive
         * operations like ECDHE. */
        mbed_pk_free( peer_pk );
    #endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    }
    else 
    {
        goto fail_internal_error;  // At least one KEM should handle the key exchange message 
    }

#endif /* MBEDTLS_KEM_WITH_SERVER_SIGNATURE_ENABLED */

finish:  
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse server key exchange" ) );
    ssl->state++;
    return 0; 
//finish_skip_key_exchange: 
//    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse server key exchange" ) );
//    ssl->state++;
//    return( 0 );



    // --- Error handling --- 
fail_read_record:
    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", rc ); goto fail; 
fail_decrypt_error: 
    mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR );
    MBEDTLS_SSL_DEBUG_RET( 1, "mbed_pk_verify", rc ); goto fail; 
fail_type_mismatch:
    mbedtls_ssl_send_alert_message( ssl,MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE );
    rc = MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH; goto fail; 
fail_illegal_parameter:
    mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER );
    rc = MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER; goto fail; 
fail_decode_error:
    mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
    rc = MBEDTLS_ERR_SSL_DECODE_ERROR; goto fail; 
fail_unexpected_message:
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "server key exchange message must not be skipped" ) );
    mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
    rc =  MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE; goto fail; 
fail_internal_error: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    rc = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
fail:
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
    return rc; 
}


/******************************************************************************
 * Description: Create the TLS client key exchange message (Step 3 in KEM process)   
 *              Step 1 : write_server_key_exchange (created by server)  
 *              Step 2 : parse_server_key_exchange (parsed by client)  
 *              Step 3 : write_client_key_exchange (created by client)  
 *              Step 4 : parse_client_key_exchange (parsed by server)
 *              After step 4 client and server have the same shared secret (premaster) 
 *
 * Arguments:   ssl -  ssl context pointer
 * 
 * result:      TRUE/FALSE  
 *****************************************************************************/
int ssl_pkwrap_write_client_key_exchange( sslctx_t  *ssl )
{
    ciphersuite_t     *suite_info = ssl->handshake->ciphersuite_info;
    kemctx_t          *kem_ctx = &ssl->handshake->kem_ctx;
    size_t             header_len = 0, content_len = 0;
    int                rc;


    /*---------------------Code ----------------------------------------------*/
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write client key exchange" ) );

    if (ssl_ciphersuite_uses_eph_kem_key( suite_info ) == TRUE)  // KEM key is ephemeral
    {
        uint8_t *p, *shared; 
        size_t   size, sh_size;
 

        // --- Generate the key required for DH exchnaged   
        if( (rc = ssl_kem_genkey_eph( kem_ctx, ssl, KEM_STEP3)) < 0) 
            goto fail; 

        if( kem_ctx->premaster[0] != 0)  // The premaster secret should be all zeros at this point 
            goto fail_internal_error; 
        header_len = 4;

        p       = ssl->out_msg + header_len;
        size    = MBEDTLS_SSL_OUT_CONTENT_LEN - header_len;
        shared  = kem_ctx->premaster;
        sh_size = KEM_PREMASTER_SIZE; 

        // --- Generate and write the KEM based on the prv key and peer key info 
        if ((rc = mbed_pk_kem_gen( kem_ctx->kem_key, kem_ctx->kem_peerkey, MBED_CAPMODE_PKCS1_5, KEM_SHARED_BLOCK_SIZE, 
                                   shared, sh_size, &kem_ctx->pms_len, p, size, &content_len)) != 0) 
        {
            goto fail; 
        }
        MBEDTLS_SSL_DEBUG_BUF( 3, "client shared secret", shared, kem_ctx->pms_len ); // TODO: To be removed 
    }
    else
#if defined(MBEDTLS_KEM_SOME_PSK_ENABLED)
    if( mbedtls_ssl_ciphersuite_uses_psk( suite_info ) )
    {
        /*
         * opaque psk_identity<0..2^16-1>;
         */
        if( ssl_conf_has_static_psk( ssl->conf ) == 0 )
        {
            /* We don't offer PSK suites if we don't have a PSK,
             * and we check that the server's choice is among the
             * ciphersuites we offered, so this should never happen. */
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        header_len = 4;
        content_len = ssl->conf->psk_identity_len;

        if( header_len + 2 + content_len > MBEDTLS_SSL_OUT_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1,
                ( "psk identity too long or SSL buffer too short" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        ssl->out_msg[header_len++] = (uint8_t)( content_len >> 8 );
        ssl->out_msg[header_len++] = (uint8_t)( content_len      );

        memcpy( ssl->out_msg + header_len,
                ssl->conf->psk_identity,
                ssl->conf->psk_identity_len );
        header_len += ssl->conf->psk_identity_len;

      #if defined(MBEDTLS_KEM_PSK_ENABLED)
        if( suite_info->key_exchange == MBEDTLS_KEM_PSK )
        {
            content_len = 0;
        }
        else
     #endif
     #if defined(MBEDTLS_KEM_RSA_PSK_ENABLED)
        if( suite_info->key_exchange == MBEDTLS_KEM_RSA_PSK )
        {
            if( ( rc = ssl_write_encrypted_pms( ssl, header_len, &content_len, 2 ) ) != 0 )
                return( rc );
        }
        else
     #endif  // MBEDTLS_KEM_RSA_PSK_ENABLED
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        if( ( rc = mbedtls_ssl_psk_derive_premaster( ssl, suite_info->key_exchange ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
                "mbedtls_ssl_psk_derive_premaster", rc );
            return( rc );
        }
    }
    else
#endif /* MBEDTLS_KEM_SOME_PSK_ENABLED */

#if defined(MBEDTLS_KEM_RSA_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_RSA )
    {
        header_len = 4;
        if( ( rc = ssl_write_encrypted_pms( ssl, header_len, &content_len, 0 ) ) != 0 )
            return( rc );
    }
    else
#endif /* MBEDTLS_KEM_RSA_ENABLED */
#if defined(MBEDTLS_KEM_ECJPAKE_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_ECJPAKE )
    {
        header_len = 4;

        rc = mbedtls_ecjpake_write_round_two( &ssl->handshake->ecjpake_ctx,
                ssl->out_msg + header_len,
                MBEDTLS_SSL_OUT_CONTENT_LEN - header_len,
                &content_len,
                ssl->conf->f_rng, ssl->conf->p_rng );
        if( rc != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecjpake_write_round_two", rc );
            return( rc );
        }

        rc = mbedtls_ecjpake_derive_secret( &ssl->handshake->ecjpake_ctx,
                ssl->handshake->premaster, 32, &ssl->handshake->kem_ctx.pms_len,
                ssl->conf->f_rng, ssl->conf->p_rng );
        if( rc != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecjpake_derive_secret", rc );
            return( rc );
        }
    }
    else
#endif /* MBEDTLS_KEM_RSA_ENABLED */
    {
        goto fail_internal_error;
    }

    ssl->out_msglen  = header_len + content_len;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE;

    ssl->state++;

    if( ( rc = mbedtls_ssl_write_handshake_msg( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_handshake_msg", rc );
        return( rc );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write client key exchange" ) );

    ssl->out_msglen  = header_len + content_len;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE;

    return( 0 );


    // --- Error handling --- 
fail_internal_error: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    rc = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
fail: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_pkwrap_write_client_key_exchange() failed" ) );
    return rc; 
}



/******************************************************************************
 * Description: Parse the TLS client key exchange message (Step 4) 
 *              Step 1 : write_server_key_exchange (created by server)  
 *              Step 2 : parse_server_key_exchange (parsed by client)  
 *              Step 3 : write_client_key_exchange (created by client)  
 *              Step 4 : parse_client_key_exchange (parsed by server)
 *              After step 4 client and server have the same shared secret (premaster) 
 *
 * Arguments:   ssl -  ssl context pointer
 * 
 * result:      TRUE/FALSE  
 *****************************************************************************/
int ssl_pkwrap_parse_client_key_exchange( sslctx_t *ssl )
{
    ciphersuite_t     *suite_info = ssl->handshake->ciphersuite_info;
    kemctx_t          *kem_ctx = &ssl->handshake->kem_ctx;
    uint8_t           *p, *end;
    int                rc;

    /*---------------------Code ----------------------------------------------*/
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse client key exchange" ) );

  #if defined(MBEDTLS_SSL_ASYNC_PRIVATE) &&( defined(MBEDTLS_KEM_RSA_ENABLED) || defined(MBEDTLS_KEM_RSA_PSK_ENABLED) )
    if( ( ciphersuite_info->key_exchange == MBEDTLS_KEM_RSA_PSK || ciphersuite_info->key_exchange == MBEDTLS_KEM_RSA ) &&
        ( ssl->handshake->async_in_progress != 0 ) )
    {
        /* We've already read a record and there is an asynchronous
         * operation in progress to decrypt it. So skip reading the
         * record. */
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "will resume decryption of previously-read record" ) );
    }
    else
  #endif
    if( ( rc = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
        goto fail_read_record;

    p   = ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl );
    end = ssl->in_msg + ssl->in_hslen;

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
        goto fail_msg_handshake; 
    
    if( ssl->in_msg[0] != MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE )
        goto fail_msg_handshake; 

    if (ssl_ciphersuite_uses_eph_kem_key( suite_info ) == TRUE)  // key is ephemeral
    {
        uint8_t  *shared; 
        size_t    size, sh_size, consumed; 

        size    = (size_t)(end-p);      // KEM data size 
        shared  = kem_ctx->premaster;
        sh_size = KEM_PREMASTER_SIZE;   // premaster secret size 

        // Parse the KEM to extract the shared secret 
        if( ( rc = mbed_pk_kem_extract( kem_ctx->kem_key,  MBED_CAPMODE_PKCS1_5, KEM_SHARED_BLOCK_SIZE, 
                                        shared, sh_size, &kem_ctx->pms_len, p, size, &consumed) ) != 0) 
        {
            goto fail; 
        }
        p += consumed; 
        MBEDTLS_SSL_DEBUG_BUF( 3, "server shared secret", shared, kem_ctx->pms_len ); 
    }
    else
  #if defined(MBEDTLS_KEM_PSK_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_PSK )
    {
        if( ( rc = ssl_parse_client_psk_identity( ssl, &p, end ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_client_psk_identity" ), rc );
            return( rc );
        }

        if( p != end )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange" ) );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        if( ( rc = mbedtls_ssl_psk_derive_premaster( ssl, suite_info->key_exchange ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_psk_derive_premaster", rc );
            return( rc );
        }
    }
    else
 #endif /* MBEDTLS_KEM_PSK_ENABLED */
 #if defined(MBEDTLS_KEM_RSA_PSK_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_RSA_PSK )
    {
      #if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
        if ( ssl->handshake->async_in_progress != 0 )
        {
            /* There is an asynchronous operation in progress to
             * decrypt the encrypted premaster secret, so skip
             * directly to resuming this operation. */
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "PSK identity already parsed" ) );
            /* Update p to skip the PSK identity. ssl_parse_encrypted_pms
             * won't actually use it, but maintain p anyway for robustness. */
            p += ssl->conf->psk_identity_len + 2;
        }
        else
      #endif /* MBEDTLS_SSL_ASYNC_PRIVATE */
        if( ( rc = ssl_parse_client_psk_identity( ssl, &p, end ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_client_psk_identity" ), rc );
            return( rc );
        }

        if( ( rc = ssl_parse_encrypted_pms( ssl, p, end, 2 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_encrypted_pms" ), rc );
            return( rc );
        }

        if( ( rc = mbedtls_ssl_psk_derive_premaster( ssl, suite_info->key_exchange ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_psk_derive_premaster", rc );
            return( rc );
        }
    }
    else
  #endif /* MBEDTLS_KEM_RSA_PSK_ENABLED */
  #if defined(MBEDTLS_KEM_DHE_PSK_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_DHE_PSK )
    {
        if( ( rc = ssl_parse_client_psk_identity( ssl, &p, end ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_client_psk_identity" ), rc );
            return( rc );
        }
        if( ( rc = ssl_parse_client_dh_public( ssl, &p, end ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_client_dh_public" ), rc );
            return( rc );
        }

        if( p != end )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange" ) );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        if( ( rc = mbedtls_ssl_psk_derive_premaster( ssl, suite_info->key_exchange ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_psk_derive_premaster", rc );
            return( rc );
        }
    }
    else
  #endif /* MBEDTLS_KEM_DHE_PSK_ENABLED */

  #if 0 
    // TODO to add PSK as a seperate PK algorithm 
  #if defined(MBEDTLS_KEM_ECDHE_PSK_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_ECDHE_PSK )
    {
        if( ( rc = ssl_parse_client_psk_identity( ssl, &p, end ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_client_psk_identity" ), rc );
            return( rc );
        }

        if( ( rc = mbedtls_ecdh_read_public( &ssl->handshake->ecdh_ctx, p, end - p ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_read_public", rc );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }


        MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx, MBEDTLS_DEBUG_ECDH_QP );

        if( ( rc = mbedtls_ssl_psk_derive_premaster( ssl, suite_info->key_exchange ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_psk_derive_premaster", rc );
            return( rc );
        }
    }
    else
  #endif /* MBEDTLS_KEM_ECDHE_PSK_ENABLED */
  #endif 

  #if defined(MBEDTLS_KEM_RSA_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEM_RSA )
    {
        if( ( rc = ssl_parse_encrypted_pms( ssl, p, end, 0 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_parse_encrypted_pms_secret" ), rc );
            return( rc );
        }
    }
    else
  #endif /* MBEDTLS_KEM_RSA_ENABLED */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ( rc = mbedtls_ssl_derive_keys( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_derive_keys", rc );
        return( rc );
    }

    ssl->state++;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse client key exchange" ) );
    return( 0 );


    // --- Error handling --- 
fail_msg_handshake: 
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
    rc = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE; goto fail; 
fail_read_record:
    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", rc );
fail:
    return( rc );
}


int mbedtls_ssl_handshake_kem_init( kemctx_t *kem_ctx )
{
    // Clear all fields
    memset(kem_ctx, 0, sizeof(kemctx_t)); 
    kem_ctx->pms_size = KEM_PREMASTER_SIZE;
    if(( kem_ctx->premaster = (uint8_t*)mbedtls_calloc(1, kem_ctx->pms_size )) == NULL)
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    return 0; 
}


void mbedtls_ssl_handshake_kem_free( ssl_kemctx_t *kem_ctx )
{
    if ( kem_ctx->premaster != NULL)
        mbedtls_free( kem_ctx->premaster); 
    mbed_pk_free( kem_ctx->kem_peerkey ); 
    mbed_pk_free( kem_ctx->kem_key ); 
    // Clear all fields  
    memset(kem_ctx, 0, sizeof(ssl_kemctx_t)); 
}


#endif /* MBEDTLS_SSL_CLI_C */
#endif // KEM_REWORK

