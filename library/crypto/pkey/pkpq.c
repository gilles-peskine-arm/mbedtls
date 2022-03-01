/*
 *  Public Key abstraction layer
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

#include "common.h"

// File switch 
#if defined(MBEDTLS_PK_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

// mbedtls global include files 
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

// mbedtls crypto include files 
#include "pkpq.h"
#include "pkpq_parse.h"
#include "crypto_util.h"

#define LOGS_PREFIX "  PK: "
#include "crypto_common.h"

//#include "mbedtls/platform_util.h"
//#include "mbedtls/error.h"

#if defined(MBEDTLS_RSA_C)
  #include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
  #include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
  #include "mbedtls/ecdsa.h"
#endif



/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Local Functions  -----------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
 * Helper for mbed_pk_sign and mbed_pk_verify
 * ---------------------------------------------------------------------------*/
static inline int pk_hashlen_helper( mdtype_e md_alg, size_t *hash_len )
{
    const mbedtls_md_info_t *md_info;

    if( *hash_len != 0 )
        return( 0 );

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        return( -1 );

    *hash_len = mbedtls_md_get_size( md_info );
    return( 0 );
}


#if defined(MBEDTLS_ECDSA_C) && defined(mbed_ECP_RESTARTABLE)
/* ---------------------------------------------------------------------------
 * Helper to set up a restart context if needed
 * ---------------------------------------------------------------------------*/
static int pk_restart_setup( mbedtls_pk_restart_ctx *ctx,  const mbed_pkinfo_t *info )
{
    /* Don't do anything if already set up or invalid */
    if( ctx == NULL || ctx->pkinfo != NULL )
        return( 0 );

    /* Should never happen when we're called */
    if( info->rs_alloc_func == NULL || info->rs_free_func == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->rs_ctx = info->rs_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pkinfo = info;

    return( 0 );
}
#endif /* MBEDTLS_ECDSA_C && mbed_ECP_RESTARTABLE */



/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Global Functions -----------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
 * Description: Check if the two pktypes are compatible 
 *
 * Arguments:   pktype      - pk type 1
 *              pktype_cmp  - pk ype to compare against
 * 
 * result:      TRUE/FALSE 
 *****************************************************************************/
int pkey_can_do(pktype_e pktype, pktype_e pktype_cmp)
{
    // Elliptical curve is a special case 
    if( pktype_cmp == MBEDTLS_PK_ECDSA) 
    {
        if ( pktype == MBEDTLS_PK_ECDSA || pktype == MBEDTLS_PK_ECKEY)
            return TRUE;  
    } 
    else if( pktype_cmp == MBEDTLS_PK_ECKEY_DH) 
    {
        if ( pktype == MBEDTLS_PK_ECKEY_DH || pktype == MBEDTLS_PK_ECKEY)
            return TRUE;  
    } 
    else if( pktype_cmp == MBEDTLS_PK_ECKEY) 
    { 
        if ( pktype == MBEDTLS_PK_ECKEY_DH || pktype == MBEDTLS_PK_ECKEY)
            return TRUE;  
    }
    else if ( pktype_cmp == pktype)  // generic  
        return TRUE;  

    return FALSE; 
}


/* ---------------------------------------------------------------------------
 *   Access the PK type
 * ---------------------------------------------------------------------------*/
pktype_e  pkey_get_type( pkfull_t *pkfull)
{
   return pkfull->pkinfo->pktype;
}


/******************************************************************************
 * Description: Get the name of the algorithm 
 *
 * Arguments:   pkfull      - PK full context 
 *****************************************************************************/
const char *pkey_get_name(pkfull_t *pkfull)
{
    return pkfull->pkinfo->get_keyparams( pkfull->pkctx )->name; 
}

/******************************************************************************
 * Description: Get the signature length of the algorithm 
 *
 * Arguments:   pkfull      - PK full context 
 *****************************************************************************/
size_t pkey_get_siglen(pkfull_t *pkfull)
{
    return pkfull->pkinfo->get_keyparams( pkfull->pkctx )->sig_len; 
}

/******************************************************************************
 * Description: Get the shared secret length of the algorithm 
 *
 * Arguments:   pkfull      - PK full context 
 *****************************************************************************/
size_t pkey_get_sslen(pkfull_t *pkfull)
{
    return pkfull->pkinfo->get_keyparams( pkfull->pkctx )->ss_len; 
}

/******************************************************************************
 * Description: Get the cipher text length of the algorithm 
 *
 * Arguments:   pkfull      - PK full context 
 *****************************************************************************/
size_t pkey_get_ctlen(pkfull_t *pkfull)
{
    return pkfull->pkinfo->get_keyparams( pkfull->pkctx )->ct_len; 
}


/******************************************************************************
 * Description: Setup a full key context 
 *
 * Arguments:   pkfull  - pointer to the context
 *              pktype  - public key type 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int pkey_pkfull_setup(  pkfull_t *pkfull, pktop_t *pktop, pktype_e pktype)
{
    struct pkfull_s *pkfull_mod = (struct pkfull_s *)pkfull; // Need to modify the struct 
    pkinfo_t        *pkinfo;

    /*---------------------Code ----------------------------------------------*/
    if ( pkfull == NULL || pkfull->pkinfo != NULL)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    
    pkfull_mod->pktop = pktop;   // Set this first
    if( (pkinfo = pkey_pkinfo_from_type( pktype )) == NULL) 
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;

    if (( pkfull_mod->pkctx = pkinfo->ctx_alloc_func(pkfull)) == NULL)
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    
    pkfull_mod->pkinfo = pkinfo;   
    return SUCCESS;
}


/******************************************************************************
 * Description: Free a full key context  
 *
 * Arguments:   pkfull   - PK full context 
 * 
 * result:      NULL 
 *****************************************************************************/
void *pkey_free_pkfull( struct pkfull_s *pkfull)
{
    pkinfo_t  *pkinfo; 
    void      *pkctx; 

    if ( pkfull != NULL) {

        pkctx  = pkfull->pkctx; 
        pkinfo = pkfull->pkinfo; 
        if ( pkinfo != NULL) 
            pkinfo->ctx_free_func( pkctx );

        mbedtls_platform_zeroize( pkfull, sizeof( pkfull_t));
    }
    return mbed_free(pkfull);
}


/******************************************************************************
 * Description: Add a fullkey to the hybrid top key context    
 *
 * Arguments:   pktop   - Top level context
 *              pkfull  - 'Full' key context  
 * 
 * result:       0 on success or error code on failure 
 *****************************************************************************/
int pkey_add_fullkey_to_list(pktop_t *pktop, pkfull_t *pkfull)
{
    struct pktop_s  *pktop_mod = (struct pktop_s *)pktop; //modify-able version of pktop
    pkinfo_t        *pkinfo;
    nistlevel_e      nist_level; 
    pk_keyparams_t  *kparms; 
    size_t           len;
    size_t           hyb_len;        // Combined Signature length of all keys
    hybpk_t          hybpk_alg;  
    int              is_pub;         // Flag for whether the key is a public key
    int              dsa_support;    // Flag indicating digital signature algorthm support
    int              kem_support;    // Flag indicating key exchange support
    int              i, rc;


    /*---------------------Code ----------------------------------------------*/
    //  Add a new key to the hydrid key.
    pktop_mod->pkfull_list[pktop_mod->num_keys++] = pkfull;

    // Update the top level information with the new key info
    dsa_support = TRUE;
    kem_support = TRUE;
    hyb_len     = 0;
    is_pub      = -1;
    hybpk_alg   = 0; 
    nist_level  = MBED_NIST_LEVEL_NONE; 

    for (i = 0; i < pktop_mod->num_keys; i++)
    {
        pkfull = pktop_mod->pkfull_list[i];

        // Make sure not to combine public and private keys
        if (is_pub == -1)
            is_pub = pkfull->is_pub;
        if (pkfull->is_pub != is_pub)
            goto fail_incompatible;

        pkinfo = (pkinfo_t *)pkfull->pkinfo;
        hybpk_alg += (pkinfo->pktype << (i*PKEY_COMB_TYPE_SHIFT));

        kparms = pkinfo->get_keyparams( pkfull->pkctx);
        hyb_len += kparms->sig_len;
        if (pkinfo->encap_func == NULL && pkinfo->dh_func == NULL)
            kem_support = FALSE;     // At least one key doesn't support key exchange
        if (pkinfo->sign_func == NULL)
            dsa_support = FALSE;     // At least one key doesn't support digital signatures

        // --- Calculate the overall NIST security level 
        if ( nist_level == MBED_NIST_LEVEL_NONE)
            nist_level = pkfull->nist_level;
        else if ( (pkfull->nist_level != MBED_NIST_LEVEL_NONE) && (pkfull->nist_level < nist_level) )
            nist_level = pkfull->nist_level;   // Pick the lowest value  
    }
    if (dsa_support == FALSE && kem_support == FALSE)  // This key would be useless
        goto fail_incompatible;

    // --- The new key is good, the pktop fields can now be updated with the new key data 
   
    // --- Concatenate all names of the keys at the top level.
    len = strlen( pktop_mod->hybrid_name );
    if (pktop_mod->num_keys > 1)
        len += snprintf( pktop_mod->hybrid_name + len, sizeof(pktop_mod->hybrid_name) - len - 1, "-" );

    // Make the comnpiler happy 
    pkinfo = (pkinfo_t *)pkfull->pkinfo;
    kparms = pkinfo->get_keyparams( pkfull->pkctx);
    snprintf( pktop_mod->hybrid_name + len, sizeof(pktop_mod->hybrid_name) - len - 1, "%s", kparms->name );

    // Update top level flags and sizes
    pktop_mod->hybpk_alg   = hybpk_alg; 
    pktop_mod->hyb_len     = hyb_len;
    pktop_mod->dsa_support = dsa_support;
    pktop_mod->kem_support = kem_support;
    pktop_mod->is_pub      = is_pub;
    pktop_mod->nist_level  = nist_level;
    return SUCCESS;


fail_incompatible:
    // Remove the added key from the list
    pktop_mod->pkfull_list[pktop_mod->num_keys--] = NULL;
    rc = MBEDTLS_ERR_PK_INCOMPATIBLE_ALGO;
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc );
    return rc;
}


/******************************************************************************
 * Description: Get the Random Number Generator info associated with the key  
 *
 * Arguments:   pktop - PK top reference  
 * 
 * result:      SUCCESS=0 or error code on failure 
 *****************************************************************************/
int pkey_get_rng_info( pktop_t *pktop, rnginfo_t **rng_out) 
{
    mbedtls_entropy_context   *entropy = NULL;
    mbedtls_ctr_drbg_context  *ctr_drbg = NULL;
    struct pk_rnginfo_s     *rng_info;
    const uint8_t             *seed_str; 
    size_t                     len; 
    int                        rc;

     
    /*---------------------Code ----------------------------------------------*/
    rng_info = (struct pk_rnginfo_s*)&pktop->rng_info;  
    if (rng_info->initialized == FALSE)
    {
        if ((ctr_drbg = (mbedtls_ctr_drbg_context *)mbed_calloc(1, sizeof(mbedtls_ctr_drbg_context))) == NULL)
            goto fail_malloc;
        if ((entropy = (mbedtls_entropy_context *)mbed_calloc(1, sizeof(mbedtls_entropy_context))) == NULL)
            goto fail_malloc;

        
        mbedtls_entropy_init(entropy);
        mbedtls_ctr_drbg_init(ctr_drbg);

        seed_str = (const uint8_t *)rng_info->seed_str;
        len      = rng_info->seed_len;

        if ((rc = mbedtls_ctr_drbg_seed(ctr_drbg, rng_info->entropy_cb, entropy, seed_str, len)) != 0)
            goto fail;
        
        rng_info->ctx         = (void*)ctr_drbg;
        rng_info->entropy     = (void*)entropy;
        rng_info->initialized = TRUE; 
    }
    *rng_out = rng_info; 
    return SUCCESS; 


    // --- Error handling --- 
fail_malloc:
    rc = MBEDTLS_ERR_PK_ALLOC_FAILED; 
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    ctr_drbg = mbed_free(ctr_drbg); 
    entropy  = mbed_free(entropy); 
    return rc;
}


/******************************************************************************
 * Description: pkbuf utility functions 
 *****************************************************************************/
void pkbuf_init(pkbuf_t *data, const uint8_t *buf, size_t size, size_t iolen) 
{
    *((uint8_t**)&data->start) = (uint8_t*)buf;
    *((uint8_t**)&data->buf)   = (uint8_t*)buf;
    *(size_t*)&data->size      = size;
    *(size_t*)&data->iolen     = iolen;
}


void pkbuf_extract(pkbuf_t *data, uint8_t **buf, size_t *size, size_t *iolen) 
{
    if (data == NULL) 
    {
        *buf   = NULL;
        *size  = 0;
        if ( iolen != NULL)
            *iolen = 0;
        return;
    }
    *buf    = (uint8_t*)data->buf;
    *size   = (size_t)data->size; 
    if ( iolen != NULL)
        *iolen  = data->iolen; 
}

// Extract to a constant buffer type 
void pkbuf_extract_const(pkbuf_t *data, const uint8_t **buf, size_t *size, size_t *iolen) 
{
    pkbuf_extract( data, (uint8_t**)buf, size, iolen); 
}  

int pkbuf_move(pkbuf_t *data, size_t len) 
{
    if ( len > data->size)
        return -1;
    *((uint8_t**)&data->buf) = (uint8_t*)data->buf + len;
    *(size_t*)&data->size    = (size_t)data->size - len;
    data->iolen              = 0;  // iolen is reset at a move 
    return 0; 
}

size_t pkbuf_total_io(pkbuf_t *data)
{
    return (size_t)(data->buf - data->start);
}


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
* Get the RNG info from the key context  
* ---------------------------------------------------------------------------*/
int mbed_pk_get_rnginfo( mbed_pktop_t *pktop_ref, mbed_rng_cb_t *f_rng, void **p_rng)
{
    pktop_t    *pktop = (pktop_t*)pktop_ref;   // top level key info  
    rnginfo_t  *rng; 
    int         rc; 

    /*---------------------Code ----------------------------------------------*/
    if(( rc = pkey_get_rng_info( pktop, &rng)) != SUCCESS)
        goto fail; 
    *f_rng = rng->cb; 
    *p_rng = rng->ctx; 
    return SUCCESS; 

    // --- Error handling --- 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return(rc);                                                                                        
}

/* ---------------------------------------------------------------------------
* Initialise a pktop structure 
* ---------------------------------------------------------------------------*/
int mbed_pk_init(mbed_pktop_t **pktop_ref, mbed_rng_cb_t  rng_cb, entropy_cb_t entropy_cb, const char *seed_str)
{
    struct pktop_s       *pktop;
    struct pk_rnginfo_s  *rng_info;
    int                   rc;


    /*---------------------Code ----------------------------------------------*/
    if ( *pktop_ref != NULL)
    {
        LOGE("%s(): pktop_ref pointer MUST be NULL to call this function !!!!!", __func__); 
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    }
    if ((pktop = (struct pktop_s *)mbed_calloc( 1, sizeof(pktop_t) )) == NULL)
        goto fail_malloc;

    // rng_info is defined as constant by default, but in this case we want to modify it so recast to non-const
    rng_info = (struct pk_rnginfo_s*)&pktop->rng_info; 

    rng_info->cb         = rng_cb;
    rng_info->entropy_cb = entropy_cb;

    if (rng_cb == NULL)
        rng_info->cb = MBED_RNG_DEFAULT_RNG_FUNC;
    if (entropy_cb == NULL)
        rng_info->entropy_cb = MBED_RNG_DEFAULT_ENTROPY_FUNC;

    if (seed_str == NULL)
        seed_str = "seed_str";  
    rng_info->seed_str = strndup(seed_str, PKEY_MAX_SEEDSTR_LEN); 
    rng_info->seed_len = strlen(rng_info->seed_str); 

    *pktop_ref = (void*)pktop; 
    return EXIT_SUCCESS;

    // --- Error handling --- 
fail_malloc:
    rc = MBEDTLS_ERR_PK_ALLOC_FAILED;  
    // --- clean up ---
    *pktop_ref = mbed_pk_free((void *)pktop);
    return rc;
}


/* ---------------------------------------------------------------------------
 *  Free (the components of) a mbed_pktop structure 
 * ---------------------------------------------------------------------------*/
void *mbed_pk_free( mbed_pktop_t *pktop_ref )
{
    struct pktop_s   *pktop = (struct pktop_s *)pktop_ref;   // top level key info  
    rnginfo_t        *rng_info;
    int               i; 

    /*---------------------Code ----------------------------------------------*/
    if( pktop == NULL )
        return NULL;
    
    for (i=0; i < pktop->num_keys; i++ ) {
        pkey_free_pkfull((struct pkfull_s *)pktop->pkfull_list[i]); 
    }

    rng_info = &pktop->rng_info;
    if (rng_info->ctx != NULL )
        mbedtls_ctr_drbg_free( (mbedtls_ctr_drbg_context *)rng_info->ctx );
    if (rng_info->entropy != NULL )
        mbedtls_entropy_free((mbedtls_entropy_context *)rng_info->entropy);
    mbed_free( rng_info->seed_str);
 
    mbedtls_platform_zeroize( pktop, sizeof( pktop_t));
    mbed_free(pktop); 
    return NULL; 
}



/* ---------------------------------------------------------------------------
 *   Verify a signature (restartable)
 * ---------------------------------------------------------------------------*/
int mbed_pk_verify_restartable( mbed_pktop_t *pktop_ref, mdtype_e  md_alg, const uint8_t *hash, size_t hash_len,
                                const uint8_t *sig,  size_t sig_len, mbedtls_pk_restart_ctx *rs_ctx )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pkfull_t  *pkfull;                        
    pkbuf_t    md_in, sig_in; 
    int        i, rc = 0; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || (md_alg == MBEDTLS_MD_NONE && hash_len == 0) || hash == NULL || sig == NULL) 
            goto fail_bad_input;

    if( pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    // Debug info 
    //if( ( rc = mbed_pk_write_key_info( pktop_ref, PK_TARGET_PUB, PK_EXPORT_BASIC, stdout)) < 0)
    //    goto fail;

  #if defined(MBEDTLS_ECDSA_C) && defined(mbed_ECP_RESTARTABLE)
    /* optimization: use non-restartable version if restart disabled */
    if( rs_ctx != NULL && mbed_ecp_restart_is_enabled() && ctx->pkinfo->verify_rs_func != NULL )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if( ( ret = pk_restart_setup( rs_ctx, ctx->pkinfo ) ) != 0 )
            return( ret );

        ret = ctx->pkinfo->verify_rs_func( ctx->pkctx, md_alg, hash, hash_len, sig, sig_len, rs_ctx );

        if( ret != MBEDTLS_ERR_ECP_IN_PROGRESS )
            mbed_pk_restart_free( rs_ctx );

        return( ret );
    }
  #else /* MBEDTLS_ECDSA_C && mbed_ECP_RESTARTABLE */
    (void) rs_ctx;
  #endif /* MBEDTLS_ECDSA_C && mbed_ECP_RESTARTABLE */

    // verify signature for each key in pktop context 
    pkbuf_init( &md_in, hash, hash_len, 0); 
    pkbuf_init( &sig_in, sig, sig_len, 0); 
    for (i=0; i < pktop->num_keys; i++) {

        pkfull = pktop->pkfull_list[i]; 

        //  Run verify operation on each key 
        if( (rc = pkfull->pkinfo->vrfy_func(pkfull->pkctx, md_alg, &md_in, &sig_in, rs_ctx)) != EXIT_SUCCESS)
            goto fail;
        pkbuf_move( &sig_in, sig_in.iolen); // Move the signature buffer to the next signature 
    }
    if (sig_in.size != 0 )  // All bytes should be consumed 
        goto fail_sigsize; 
    return SUCCESS;

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_sigsize: 
    rc = MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return(rc);                                                                                        
}


/* ---------------------------------------------------------------------------
 *   Verify a signature 
 * ---------------------------------------------------------------------------*/
int mbed_pk_verify( mbed_pktop_t *pktop_ref, mdtype_e md_alg, const uint8_t *hash, size_t hash_len,
                    const uint8_t *sig, size_t sig_len )
{
    return mbed_pk_verify_restartable( pktop_ref, md_alg, hash, hash_len, sig, sig_len, NULL );
}

/* ---------------------------------------------------------------------------
 *   Verify a signature 
 * ---------------------------------------------------------------------------*/
int mbed_pk_verify_ext( mbed_pktop_t *pktop_ref, mbed_hybpk_t hybpk_alg, mdtype_e md_alg, const uint8_t *hash, size_t hash_len,
                        const uint8_t *sig, size_t sig_len, const void *options )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    int        rc; 


    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || (md_alg != MBEDTLS_MD_NONE && hash_len == 0) || hash == NULL || sig == NULL) 
        goto fail_bad_input;

    if (pktop->num_keys == 0)
        goto fail_bad_input;

    if( !mbed_pk_can_do( pktop_ref, hybpk_alg ) )
        goto fail_mismatch;

    if( hybpk_alg == MBEDTLS_PK_RSASSA_PSS )
    {
   #if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
        const mbedtls_pk_rsassa_pss_options *pss_opts;
        rc = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

      #if SIZE_MAX > UINT_MAX
        if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
            goto fail_bad_input;
      #endif /* SIZE_MAX > UINT_MAX */

        if( options == NULL )
            goto fail_bad_input;

        pss_opts = (const mbedtls_pk_rsassa_pss_options *) options;

        if( sig_len < mbed_pk_get_hybrid_len( pktop_ref) )
            goto fail_verify;


        rc = mbedtls_rsa_rsassa_pss_verify_ext( (rsakey_t*)mbed_pk_get_pkctx_old( pktop_ref ),
                                                 md_alg, (unsigned int) hash_len, hash,
                                                 pss_opts->mgf1_hash_id,
                                                 pss_opts->expected_salt_len,
                                                 sig );
        if( rc != 0 )
            goto fail; 

        if( sig_len > mbed_pk_get_hybrid_len( pktop_ref ) )
            goto fail_mismatch;

        return( 0 );
      #else
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
      #endif /* MBEDTLS_RSA_C && MBEDTLS_PKCS1_V21 */
    }

    /* General case: no options */
    if( options != NULL )
        goto fail_bad_input; 

    if( (rc = mbed_pk_verify( pktop_ref, md_alg, hash, hash_len, sig, sig_len)) != SUCCESS)
        goto fail; 
    return SUCCESS; 

    // --- Error handling ---
fail_verify: 
    rc = MBEDTLS_ERR_RSA_VERIFY_FAILED; goto fail;
fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail;
fail_mismatch:
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc;
}


int mbed_pk_verify_ext_old( mbed_pktop_t *pktop_ref, mdtype_e md_alg, const uint8_t *hash, size_t hash_len,
                           const uint8_t *sig, size_t sig_len, const void *options )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pktype_e  pktype;
    int       rc; 

    if (pktop == NULL )
        goto fail_bad_input;

    pktype = (pktype_e)pktop->hybpk_alg;
    rc = mbed_pk_verify_ext( pktop_ref, pktype, md_alg, hash, hash_len, sig, sig_len, options);
    return rc;

fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    return rc;
}

/* ---------------------------------------------------------------------------
 *   Make a signature (restartable)
 * ---------------------------------------------------------------------------*/
int mbed_pk_sign_restartable(mbed_pktop_t *pktop_ref, mdtype_e md_alg, const uint8_t *hash, size_t hash_len,
                             uint8_t *sig, size_t sig_size, size_t *sig_olen, mbedtls_pk_restart_ctx *rs_ctx )
{
    pktop_t   *pktop = (pktop_t *)pktop_ref;   // top level key info
    pkfull_t  *pkfull;
    pkbuf_t    md_in, sig_out;
    int        i, rc = 0;
    (void) rs_ctx;


    /*---------------------Code ----------------------------------------------*/
    if (pktop_ref == NULL || (md_alg == MBEDTLS_MD_NONE && hash_len == 0) || hash == NULL || sig == NULL)
        goto fail_bad_input;

    if ((pktop->num_keys == 0)|| (pk_hashlen_helper(md_alg, &hash_len) != 0))
        goto fail_bad_input;

    // Debug info 
    //if( ( rc = mbed_pk_write_key_info( pktop_ref, PK_TARGET_PUB, PK_EXPORT_BASIC, stdout)) < 0)
    //    goto fail;

    // verify signature for each key in top context
    printf( "%s(): Hash len = %d\n", __func__, (int)hash_len); 
    pkbuf_init( &md_in, hash, hash_len, 0 ); 
    pkbuf_init( &sig_out, sig, sig_size, 0); 

    for (i = 0; i < pktop->num_keys; i++) {

        pkfull = pktop->pkfull_list[i];


        //  Run the sign operation on each key
        if (pkfull->pkinfo->sign_func == NULL)
            goto fail_mismatch;

        if ((rc = pkfull->pkinfo->sign_func(pkfull->pkctx, md_alg, &md_in, &sig_out, NULL)) != SUCCESS)
            goto fail;
        
        *sig_olen += sig_out.iolen;
        pkbuf_move( &sig_out, sig_out.iolen); // Move the signature buffer to the next signature 
    }
    *sig_olen = pkbuf_total_io(&sig_out);  // return the combined size of all signatures 
    return SUCCESS;

    // --- Error handling ---
fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail;
fail_mismatch:
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *sig_olen = 0; 
    return rc;
}



/* ---------------------------------------------------------------------------
 *   Make a signature
 * ---------------------------------------------------------------------------*/
int mbed_pk_sign( mbed_pktop_t *pktop_ref,  mdtype_e md_alg,  const uint8_t *hash,  size_t hash_len,
                  uint8_t *sig,  size_t sig_size,  size_t *sig_len)
{
    return( mbed_pk_sign_restartable( pktop_ref, md_alg, hash, hash_len, sig, sig_size, sig_len, NULL) );
}


/* ---------------------------------------------------------------------------
 *   Decapsulate message
 * ---------------------------------------------------------------------------*/
int mbed_pk_decap( mbed_pktop_t *pktop_ref, capmode_e mode, const uint8_t *m, size_t mlen, uint8_t *obuf, size_t osize, size_t *olen )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pkfull_t  *pkfull;                        
    pkbuf_t    m_in;       // message in 
    pkbuf_t    result;     // result of decap operation 
    int        rc = 0; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || m == NULL ||  obuf == NULL || olen == NULL ) 
        goto fail_bad_input;
    if ( mlen == 0 || osize == 0 ) 
        goto fail_bad_input;

    //  Run the decrypt operation on the first key that supports the encap func 
    pkbuf_init( &m_in, m, mlen, 0 );
    pkbuf_init( &result, obuf, osize, 0 );

    if ( pktop->num_keys > 1)  // Encap operation does not work with hybrid keys 
        goto fail_mismatch;

    pkfull = pktop->pkfull_list[0]; 

    if ( pkfull->pkinfo->decap_func == NULL) 
        goto fail_mismatch;

    //  Run the decap operation on the key 
    if ((rc = pkfull->pkinfo->decap_func(pkfull->pkctx, mode, &m_in, &result)) != EXIT_SUCCESS)
        goto fail; 
    *olen = result.iolen;
    return SUCCESS;

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_mismatch: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *olen = 0;
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 *   Encapsulate message
 * ---------------------------------------------------------------------------*/
int mbed_pk_encap( mbed_pktop_t *pktop_ref, capmode_e mode, const uint8_t *m, size_t mlen, uint8_t *obuf, size_t osize, size_t *olen)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pkfull_t  *pkfull;                        
    pkbuf_t    m_in;       // message in 
    pkbuf_t    result;     // result of decap operation 
    int        rc = 0; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || m == NULL ||  obuf == NULL || olen == NULL ) 
        goto fail_bad_input;
    if ( mlen == 0 || osize == 0 ) 
        goto fail_bad_input;

    //  Run the decrypt operation on the first key that supports the encap func 
    pkbuf_init( &m_in, m, mlen, 0 );
    pkbuf_init( &result, obuf, osize, 0 );

    if ( pktop->num_keys > 1)  // Encap operation does not work with hybrid keys 
        goto fail_mismatch;

    pkfull = pktop->pkfull_list[0]; 

    if ( pkfull->pkinfo->decap_func == NULL) 
        goto fail_mismatch;

    if( (rc = pkfull->pkinfo->encap_func(pkfull->pkctx, mode, &m_in, &result)) != EXIT_SUCCESS) 
        goto fail; 

    *olen = result.iolen;
    return SUCCESS;

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_mismatch: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *olen = 0;
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 *   Calculate the Diffie Hellman shared secret from a prv key and a pub key
 * ---------------------------------------------------------------------------*/
int mbed_pk_dh( mbed_pktop_t *pktop_prv_ref, mbed_pktop_t *pktop_peer_ref, uint8_t *shared, size_t size, size_t *olen)
{
    pktop_t   *pktop_prv  = (pktop_t *)pktop_prv_ref;   // top level key info
    pktop_t   *pktop_peer = (pktop_t *)pktop_peer_ref;  // top level key info peer (pub key)
    pkfull_t  *pkfull_prv, *pkfull_peer;
    pkinfo_t  *pkinfo;
    pkbuf_t    result;     // result of the DH operation
    int        i, rc = 0;

    /*---------------------Code ----------------------------------------------*/
    if (pktop_prv == NULL || pktop_peer == NULL || shared == NULL || olen == NULL)
        goto fail_bad_input;

    if (size == 0)
        goto fail_bad_input;

    *olen = 0;
    pkbuf_init( &result, shared, size, 0 );

    //  Run the DH operation on each key
    for (i = 0; i < pktop_prv->num_keys; i++)
    {
        if (size == 0)
            goto fail_bufsz;

        if (i >= pktop_peer->num_keys)
            goto fail_mismatch;

        pkfull_prv  = pktop_prv->pkfull_list[i];
        pkfull_peer = pktop_peer->pkfull_list[i];

        pkinfo = pkfull_prv->pkinfo; // Use the Diffie Hellman callback function from the private key

        if ( (pkinfo->dh_func == NULL)  || 
             (pkey_can_do( pkinfo->pktype, pkfull_peer->pkinfo->pktype ) == FALSE))
        {
            printf( "%s(): !!!!!!!!!! mbed_pk_can_do_single() failed  %d != %d\n", __func__, 
                    pkfull_prv->pkinfo->pktype, pkfull_peer->pkinfo->pktype ); 
            goto fail_mismatch;
        }
        //if (pkinfo->name != pkfull_peer->pkinfo->name)
        // goto fail_mismatch;

        // Calculate the Diffie Hellman shared secret ( e.g. calls eckey_dh_wrap(), rsakey_dh_wrap(),...)
        if ((rc = pkinfo->dh_func( pkfull_prv->pkctx, pkfull_peer->pkctx, &result )) != SUCCESS)
            goto fail;
        pkbuf_move( &result, result.iolen); // Move the buffer to after this shared secret slot 
    }
    *olen = pkbuf_total_io(&result);
    return SUCCESS; 


    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_bufsz: 
    rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; goto fail;
fail_mismatch: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *olen = 0;
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 *   Public key, Key exchange Mechanism, generate the shared and KEM data 
 * ---------------------------------------------------------------------------*/
int mbed_pk_kem_gen( mbed_pktop_t *pktop_prv_ref, mbed_pktop_t *pktop_peer_ref, capmode_e capmode, size_t sh_blocksz, 
                     uint8_t *shared, size_t sh_size, size_t *sh_olen, uint8_t *obuf, size_t osize, size_t *olen)
{
    pktop_t     *pktop_prv  = (pktop_t *)pktop_prv_ref;   // top level key info
    pktop_t     *pktop_peer = (pktop_t *)pktop_peer_ref;  // top level key info peer (pub key)
    pkfull_t    *pkfull_prv, *pkfull_peer;
    pkinfo_t    *pkinfo_peer;
    rnginfo_t   *rng = NULL; 
    pkbuf_t      kem_odata;       // KEM data 
    pkbuf_t      sh_data;         // Shared secret data 
    pkbuf_t      shdata_in;  
    size_t       len, ss_len, ct_len; 
    int          i, i_prv = 0, rc = 0;
    (void) sh_blocksz; 

    /*---------------------Code ----------------------------------------------*/
    // --- sanity check 
    if ( pktop_peer == NULL || sh_olen == NULL || obuf == NULL || olen == NULL || osize == 0) 
        goto fail_bad_input;
    
    *sh_olen = 0;
    *olen    = 0;
    pkbuf_init( &kem_odata, obuf, osize, 0 );
    pkbuf_init( &sh_data, shared, sh_size, 0 );

    // --- Run the key exchange operation on each key
    for (i = 0; i < pktop_peer->num_keys; i++)
    {
        pkfull_peer = pktop_peer->pkfull_list[i];
        pkinfo_peer = pkfull_peer->pkinfo;

        ss_len = pkey_get_sslen(pkfull_peer);   // Get the shared secret length of the algorithm
        // --- Check if we have enough room in the buffers 
        if (sh_data.size < ss_len)
            goto fail_bufsz;

        // --- Create the key exchange data for this key 
        if (pkinfo_peer->encap_func != NULL)
        {
            // --- check if there is enough room to add the cipher text 
            ct_len = pkey_get_ctlen(pkfull_peer);   // Get the cipher text length of the algorithm
            if ( kem_odata.size < ct_len )
                goto fail_bufsz;

            // --- Key exchange method of this key is encap/decap 
            if ( rng == NULL)
            {
                if( (rc = pkey_get_rng_info( pktop_peer, &rng)) != SUCCESS)
                    goto fail; 
            }
            // --- Create the key exchange message (random) data  
            if ((rc = rng->cb( rng->ctx, (uint8_t*)sh_data.buf, ss_len )) != 0)
                goto fail;
            pkbuf_init( &shdata_in, sh_data.buf, ss_len, 0 );  // Define an input buffer for the encap function        
            pkbuf_move( &sh_data, ss_len);                      // Move the shared data buffer

            // --- Encapsulate the KEM shared data with the public key. 
            rc = pkinfo_peer->encap_func( pkfull_peer->pkctx, capmode, &shdata_in, &kem_odata );
            pkbuf_move(&kem_odata, kem_odata.iolen);
        }
        else if (pkinfo_peer->dh_func != NULL ) 
        {
            // --- Key exchange method of this key is Diffie Hellman
            // --- We need to use the private key to generate the shared secret 
            // --- There is ONLY an associated private key for DH exchanges
            if (pktop_prv == NULL )
                goto fail_bad_input;
            pkfull_prv = pktop_prv->pkfull_list[i_prv++];

            // --- Verify that the peer key is of the same type as the private key  
            if ( pkey_can_do( pkfull_prv->pkinfo->pktype, pkinfo_peer->pktype) == FALSE)
                goto fail_mismatch;

            // --- Do the DH operation to create the shared secret 
            rc = pkinfo_peer->dh_func( pkfull_prv->pkctx, pkfull_peer->pkctx, &sh_data); 
            pkbuf_move(&sh_data, sh_data.iolen);         // Move the shared data buffer

            // --- export the public key ( call will fail if there is not enough room in the buffer) 
            rc = pkfull_prv->pkinfo->export_func( pkfull_prv->pkctx, PK_TARGET_PUBSSL_RESP, PK_EXPORT_DER, &kem_odata);
            len = kem_odata.iolen;  
            // --- the export function writes from end to begin -> move resulting data to the start of the buffer
            memmove( (void*)kem_odata.buf, kem_odata.buf + kem_odata.size - len, len ); 
            pkbuf_move(&kem_odata, len);
        }
        else 
            rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
        if (rc < 0) 
            goto fail; 
    }
    *sh_olen = pkbuf_total_io(&sh_data);
    *olen    = pkbuf_total_io(&kem_odata);
    // util_dump( (uint8_t*)sh_data.start, *sh_olen, "shared_data"); 
    //util_dump( (uint8_t*)kem_odata.start,  *olen, "KEM_data" ); 
    return SUCCESS; 


    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_bufsz: 
    rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; goto fail;
fail_mismatch: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *sh_olen = 0; 
    *olen = 0;
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 *   Public key, Key exchange Mechanism, extract the shared data 
 * ---------------------------------------------------------------------------*/
int mbed_pk_kem_extract( mbed_pktop_t *pktop_prv_ref, capmode_e capmode, size_t sh_blocksz,
                     uint8_t *shared, size_t sh_size, size_t *sh_olen, uint8_t *ibuf, size_t isize, size_t *ilen)
{
    pktop_t      *pktop_prv = (pktop_t *)pktop_prv_ref;    // top level key info
    mbed_pktop_t *pktop_peer_ref = NULL;
    pkfull_t     *pkfull_prv, *pkfull_peer;                                                        
    pkinfo_t     *pkinfo_prv, *pkinfo_peer;                                                        
    pkbuf_t       kem_idata;       // KEM data buffer 
    pkbuf_t       sh_data;         // Shared secret data buffer 
    pkbuf_t       shdata_in;  
    pktype_e      pktype;  
    uint8_t      *p, *end;                                                                         
    size_t        consumed, ss_len;                                                                 
    int           i, rc = 0;                                                                       
    (void) sh_blocksz; 

    /*---------------------Code ----------------------------------------------*/
    if (pktop_prv == NULL || shared == NULL || ibuf == NULL)
        goto fail_bad_input;
    if (sh_size == 0 || isize == 0)
        goto fail_bad_input;

    pkbuf_init( &kem_idata, ibuf, isize, 0);
    pkbuf_init( &sh_data, shared, sh_size, 0);

    // --- Run the key exchange operation on each key
    for (i = 0; i < pktop_prv->num_keys; i++)
    {
        pkfull_prv  = pktop_prv->pkfull_list[i];
        pkinfo_prv  = pkfull_prv->pkinfo;

        ss_len = pkey_get_sslen(pkfull_prv);   // Get the shared secret length of the algorithm
        
        // --- Check that the we have enough room in the shared buffer 
        if (sh_data.size < ss_len) 
            goto fail_bufsz;

        // --- Create the key exchange data for this key 
        if (pkinfo_prv->decap_func != NULL)
        {
            pkbuf_init( &shdata_in, sh_data.buf, ss_len, 0 );  // Define an input buffer for the decap function        
            // Write the decapsulated result to the shared secret data buffer 
            rc = pkinfo_prv->decap_func( pkfull_prv->pkctx, capmode, &kem_idata, &shdata_in );
            pkbuf_move(&sh_data, shdata_in.iolen);         // Move the shared data buffer

            consumed = pkey_get_ctlen(pkfull_prv);         // Get the cipher text length of the algorithm
            pkbuf_move( &kem_idata, consumed);
        }
        else if (pkfull_prv->pkinfo->dh_func != NULL) 
        {
            // --- Key exchange method of this key is Diffie Hellman
            // --- The peer public key is expected in the KEM to generate the shared secret 
            mbed_pk_init( &pktop_peer_ref, NULL, NULL, NULL);
            // --- import the public key 

            p     = (uint8_t*)kem_idata.buf; 
            end    = p + kem_idata.size; 
            pktype = pkinfo_prv->pktype; // Type need to match the prv key 
            // util_dump(p, (end-p), "SSL response public DH key");
            
            // --- The private key associated wit the peer key (pkfull_prv->pkctx) 
            // --- in provided in case algorithm information is needed 
            if ((rc = pkey_parse_pubkey_ssl( (pktop_t *)pktop_peer_ref, PK_TARGET_PUBSSL_RESP, 
                                              pktype, (void *)pkfull_prv->pkctx,  &p, end )) < 0)
            {
                goto fail; 
            }

            consumed = (size_t)(p- kem_idata.buf);   // bytes consumed by the key import
            pkbuf_move( &kem_idata, consumed);

            pkfull_peer = ((pktop_t*)pktop_peer_ref)->pkfull_list[0];  // Only one key loaded 
            pkinfo_peer = pkfull_peer->pkinfo;

            // --- Verify that the peer key is of the same type as the private key  
            if ( pkey_can_do( pkfull_prv->pkinfo->pktype, pkinfo_peer->pktype) == FALSE)
                goto fail_mismatch;

            // --- calculate the shared secret  
            rc = pkinfo_peer->dh_func( pkfull_prv->pkctx, pkfull_peer->pkctx, &sh_data); 
            // --- check the returned length is the same as the algorithm length 
            if (sh_data.iolen != ss_len )
            {
                LOGE("%s(): ss_len mismatch (%d != %d) for type %d\n", __func__, (int)sh_data.iolen, (int)ss_len, (int)pkinfo_peer->pktype ); 
            }
            pkbuf_move(&sh_data, sh_data.iolen);         // Move the shared data buffer with size of shared secret
            pkinfo_peer = mbed_pk_free(pktop_peer_ref);  // Free the peer key 
        }
        else 
            rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
        if (rc != SUCCESS)
            goto fail; 

    }
    *sh_olen = pkbuf_total_io(&sh_data);
    *ilen    = pkbuf_total_io(&kem_idata);
    // util_dump( (uint8_t*)sh_data.start, *sh_olen, "shared_data received"); 
    return SUCCESS; 

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_bufsz: 
    rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; goto fail;
fail_mismatch: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    pktop_peer_ref = mbed_pk_free(pktop_peer_ref);  // Cleanup if needed 
    *sh_olen = 0; 
    *ilen    = 0;
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 *   Check public-private key pair
 * ---------------------------------------------------------------------------*/
int mbed_pk_check_pair( mbed_pktop_t *pktop_ref_pub, mbed_pktop_t *pktop_ref_prv)
{
    pktop_t    *pktop_pub = (pktop_t*)pktop_ref_pub;   // top level key info  
    pktop_t    *pktop_prv = (pktop_t*)pktop_ref_prv;   // top level key info  
    pkfull_t   *pkfull_pub, *pkfull_prv;                        
    pkinfo_t   *pkinfo_pub, *pkinfo_prv;   
    void       *pkctx_pub,  *pkctx_prv;    
    int         i, rc = 0;                   


    /*---------------------Code ----------------------------------------------*/
    if ( pktop_pub == NULL || pktop_prv == NULL ) 
        goto fail_bad_input;

    if (  pktop_pub->num_keys == 0 || (pktop_pub->num_keys != pktop_prv->num_keys) ) 
        goto fail_bad_input;

    //  Run the check pair operation on each key 
    for (i=0; i < pktop_pub->num_keys; i++) {

        pkfull_pub = pktop_pub->pkfull_list[i]; 
        pkinfo_pub = pkfull_pub->pkinfo; 
        pkctx_pub  = pkfull_pub->pkctx; 

        pkfull_prv = pktop_prv->pkfull_list[i]; 
        pkinfo_prv = pkfull_prv->pkinfo; 
        pkctx_prv  = pkfull_prv->pkctx; 

        if( pkinfo_pub == NULL || pkinfo_prv == NULL) 
            goto fail_bad_input;
        if ( pkinfo_pub->check_pair_func == NULL || pkinfo_prv->check_pair_func == NULL) 
            goto fail_bad_input;

        //Check if key types match 
        if( pkinfo_prv->pktype == MBEDTLS_PK_RSA_ALT )
        {
            if( pkinfo_pub->pktype != MBEDTLS_PK_RSA )
                return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
        }
        else if ( pkinfo_pub->pktype != pkinfo_prv->pktype) 
            goto fail_mismatch;
 
        if( (rc = pkinfo_prv->check_pair_func( pkctx_pub, pkctx_prv)) != SUCCESS) 
            goto fail;
    }
    return SUCCESS;


    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_mismatch: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 *   Generate an additional key
 *  
 *   keygen_params: text string with key generation parameters (will be tokenized) 
 *  
 *   returns:       key_index or error 
 * ---------------------------------------------------------------------------*/
int mbed_pk_keygen(mbed_pktop_t *pktop_ref, pktype_e pktype, char *keygen_params)
{
    pktop_t          *pktop = (pktop_t *)pktop_ref;   // top level key info  
    struct pkfull_s  *pkfull = NULL;                         
    pkinfo_t         *pkinfo; 
    int               rc; 

    /*---------------------Code ----------------------------------------------*/
    if(pktop == NULL )
        goto fail_bad_input;
    if (pktop->num_keys >= PKEY_MAX_FULL_KEYS ) 
        goto fail_num_keys;

    if( (pkfull = (struct pkfull_s *)mbed_calloc(1, sizeof(pkfull_t))) == NULL) 
        goto fail_malloc; 

    if ((rc = pkey_pkfull_setup(pkfull, pktop, pktype)) != SUCCESS) 
        goto fail; 
    pkinfo = pkfull->pkinfo; 

    // Call the actual key generation function 
    if ((rc  = pkinfo->keygen_func(pkfull->pkctx, keygen_params)) != SUCCESS)
        goto fail; 
   
    // Add key to the list
    pkfull->is_pub = FALSE; 
    if( (rc = pkey_add_fullkey_to_list( pktop, pkfull)) != SUCCESS)
        goto fail; 
    return SUCCESS; 


    // --- Error handling --- 
fail_num_keys: 
    rc = MBEDTLS_ERR_PK_NUM_KEYS_ERROR; goto fail; 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_malloc: 
    rc = MBEDTLS_ERR_PK_ALLOC_FAILED; goto fail;
fail: 
    pkfull = pkey_free_pkfull(pkfull); 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/* ---------------------------------------------------------------------------
 *   Export the key info 
 * ---------------------------------------------------------------------------*/
int mbed_pk_create_subkey_ref( mbed_pktop_t *pktop_ref, mbed_pktop_t *subkeytop_ref, int key_idx )
{
    pktop_t     *pktop = (pktop_t *)pktop_ref;                   // top level key info
    pktop_t     *subkey_top = (pktop_t *)subkeytop_ref;   // top level subkey info
    pkfull_t    *subkey_full;                         
    int          rc;

    /*---------------------Code ----------------------------------------------*/
    if (pktop == NULL || subkey_top == NULL || key_idx == 0 || key_idx > pktop->num_keys)
        goto fail_bad_input;

    // Copy the full key reference 
    subkey_full = pktop->pkfull_list[key_idx - 1]; 
    pkey_add_fullkey_to_list(subkey_top, subkey_full); 
    return SUCCESS; 

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/* ---------------------------------------------------------------------------
 *   Export the key info 
 * ---------------------------------------------------------------------------*/
int mbed_pk_export_key_info( mbed_pktop_t *pktop_ref, pktarget_e target, pkexport_e level, char *buf, size_t size) 
{
    pktop_t    *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pkfull_t   *pkfull;                        
    pkbuf_t     result;     // result of export operation 
    size_t      tmp_len, total_len = 0;         
    int         i, rc = 0; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL ) 
        goto fail_bad_input;
    buf[0] = 0;
    buf[size-1] = 0;

    pkbuf_init( &result, (uint8_t*)buf, size, 0); 

    //  Run the export operation on each key 
    for (i=0; i < pktop->num_keys; i++) 
    {
        pkfull = pktop->pkfull_list[i]; 

        if (pkfull->pkinfo->export_func == NULL)
            goto fail_mismatch;

        if ( pktop->num_keys > 1)
        {
            tmp_len = snprintf((char*)result.buf, result.size,"\nKey #%d:\n---------------\n",i+1); 
            pkbuf_move( &result, tmp_len); // Move the start of the buffer pointer 
        }
        if( (rc = pkfull->pkinfo->export_func(pkfull->pkctx, target, level, &result)) != SUCCESS)
            goto fail; 
        pkbuf_move( &result, result.iolen); // Move the start of the buffer pointer 
    }
    total_len = pkbuf_total_io( &result); 
    return (int)total_len; 

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_mismatch: 
    rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc;                                                                                        
}

/* ---------------------------------------------------------------------------
 *   Write the key info to stdout 
 * ---------------------------------------------------------------------------*/
int mbed_pk_write_key_info( mbed_pktop_t *pktop_ref, pktarget_e target, pkexport_e level, FILE *f) 
{
    char buf[4096]; 
    int  rc;

    if(( rc = mbed_pk_export_key_info(pktop_ref,target, level, buf, sizeof(buf))) < 0) 
        return rc; 
    if (f == NULL)
        fprintf( stdout, "%s\n", buf );
    else 
        fprintf( f, "%s\n", buf );
    return 0; 
}

/* ---------------------------------------------------------------------------
 *   Get the signature oid from the key
 * ---------------------------------------------------------------------------*/
int  mbed_pk_get_signature_oid( mbed_pktop_t *pktop_ref, mdtype_e mdtype, const char **oid, size_t *oid_len )
{
    pktop_t      *pktop = (pktop_t *)pktop_ref;   // top level key info
    mbed_hybpk_t  pktype;
    int           rc;

    /*---------------------Code ----------------------------------------------*/
    if (pktop->num_keys == 1)
    {
        // Handle classic keys 
        if( mbed_pk_can_do( pktop_ref, (uint32_t)MBEDTLS_PK_RSA ) ) // Map the different RSA keys to MBEDTLS_PK_RSA
            pktype = MBEDTLS_PK_RSA;
        else if (mbed_pk_can_do( pktop_ref, (uint32_t)MBEDTLS_PK_ECDSA ))  // Map EC keys to ECDSA type 
            pktype = MBEDTLS_PK_ECDSA;
        else if (mbed_pk_can_do( pktop_ref, (uint32_t)MBEDTLS_PK_PQDSA))
        {
            pktype = MBEDTLS_PK_PQDSA;             // generic PQ OID 
            LOGE("%s() Post quantum keys not supported yet!! \n", __func__); 
            goto fail_invalid;
        }
        else 
            goto fail_invalid;

        rc =  mbedtls_oid_get_oid_by_sig_alg( pktype, mdtype, oid, oid_len );
    }
    else
    {
        // Hybrid key, has a generic "HYBRID" OID  
        rc = mbedtls_oid_get_oid_by_sig_alg( MBEDTLS_PK_HYBDSA, mdtype, oid, oid_len );
    }
    if (rc != SUCCESS)
        goto fail; 
    return SUCCESS; 
     
         
fail_invalid: 
    rc = MBEDTLS_ERR_PK_INVALID_ALG;
fail:      
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *oid_len = 0;
    return rc; 
}


/* ---------------------------------------------------------------------------
 *   Get key size in bits
 * ---------------------------------------------------------------------------*/
int  mbed_pk_get_bitlen_single( mbed_pktop_t *pktop_ref, int key_idx, size_t *bitlen )
{
    pktop_t         *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pk_keyparams_t  *kparms; 
    pkinfo_t        *pkinfo; 
    void            *pkctx; 
    int              rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || key_idx >= pktop->num_keys ) 
        goto fail_bad_input;

    pkinfo = pktop->pkfull_list[key_idx]->pkinfo;
    pkctx  = pktop->pkfull_list[key_idx]->pkctx;
    kparms = pkinfo->get_keyparams( pkctx); 
    *bitlen = kparms->sig_len * 8;  
    return SUCCESS;

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    *bitlen = 0;
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/* ---------------------------------------------------------------------------
 *   Get key size in bits
 * ---------------------------------------------------------------------------*/
mbed_nistlevel_e mbed_pk_get_nist_level( mbed_pktop_t *pktop_ref, int key_idx)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || key_idx >= pktop->num_keys ) 
        return  MBED_NIST_LEVEL_NONE; 
    return pktop->pkfull_list[key_idx]->nist_level;
}


/* ---------------------------------------------------------------------------
 *   Get key size in bits
 * ---------------------------------------------------------------------------*/
size_t mbed_pk_get_bitlen( mbed_pktop_t *pktop_ref)
{
    return ((pktop_t *)pktop_ref)->hyb_len*8; 
}

/* ---------------------------------------------------------------------------
 *   Get key size in bits
 * ---------------------------------------------------------------------------*/
int  mbed_pk_get_ec_grpid( mbed_pktop_t *pktop_ref, int key_idx, mbedtls_ecp_group_id *grpid )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    void      *pkctx;                         // key context
    eckey_t   *eckey; 
    int        rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || key_idx >= pktop->num_keys ) 
        goto fail_bad_input;
    pkctx  = pktop->pkfull_list[key_idx]->pkctx;
    eckey  = (eckey_t *)pkctx;
    *grpid = eckey->grp.id;
    return SUCCESS;

    // --- Error handling --- 
fail_bad_input: 
    *grpid = MBEDTLS_ECP_DP_NONE; 
    rc     = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/* ---------------------------------------------------------------------------
 *   Get key name
 * ---------------------------------------------------------------------------*/
int mbed_pk_get_name( mbed_pktop_t *pktop_ref, int key_idx, const char **name )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pkinfo_t  *pkinfo; 
    void      *pkctx; 
    int        rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || key_idx >= pktop->num_keys ) 
        goto fail_bad_input;

    pkinfo = pktop->pkfull_list[key_idx]->pkinfo;
    pkctx  = pktop->pkfull_list[key_idx]->pkctx;

    *name  = pkinfo->get_keyparams( pkctx)->name; 
    return SUCCESS;

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    name = NULL; 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/* ---------------------------------------------------------------------------
 *   Access the PK type
 * ---------------------------------------------------------------------------*/
int mbed_pk_get_type( mbed_pktop_t *pktop_ref, int key_idx, pktype_e *pktype)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pkinfo_t  *pkinfo; 
    int        rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || key_idx >= pktop->num_keys ) 
        goto fail_bad_input;

    pkinfo = pktop->pkfull_list[key_idx]->pkinfo;
    *pktype= pkinfo->pktype; 
    return SUCCESS; 

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    *pktype = MBEDTLS_PK_NONE; 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/* ---------------------------------------------------------------------------
 *   Get the number of keys in the hybrid key context 
 * ---------------------------------------------------------------------------*/
int mbed_pk_get_numkeys( mbed_pktop_t *pktop_ref, int *num_keys)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    int        rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL) 
        goto fail_bad_input;

    *num_keys = pktop->num_keys;
    return SUCCESS; 

// --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    *num_keys = 0;
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/* ---------------------------------------------------------------------------
 *   Export debug information
 * ---------------------------------------------------------------------------*/
int mbed_pk_debug( mbed_pktop_t *pktop_ref, int key_idx, mbedtls_pk_debug_item *items )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pkinfo_t  *pkinfo; 
    void      *pkctx; 
    int        rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( pktop_ref == NULL || key_idx >= pktop->num_keys ) 
        goto fail_bad_input;

    pkinfo = pktop->pkfull_list[key_idx]->pkinfo;
    pkctx  = pktop->pkfull_list[key_idx]->pkctx;

    pkinfo->debug_func(pkctx, items );
    return SUCCESS;

// --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/* -------------------------------------------
  *   Get key hybrid name
 * ---------------------------------------------------------------------------*/
char *mbed_pk_get_hybrid_name( mbed_pktop_t *pktop_ref)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  

    return (char*)pktop->hybrid_name;

}

/* ---------------------------------------------------------------------------
  *   Check if one of the keys in the hybrid key supports an algporithm 
 * ---------------------------------------------------------------------------*/
int mbed_pk_can_do_single( mbed_pktop_t *pktop_ref, pktype_e pktype_cmp)
{
    pktop_t    *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pktype_e    pktype; 
    int         i; 
    
    /*---------------------Code ----------------------------------------------*/
    //  Check the pktype for each each key 
    for (i=0; i < pktop->num_keys; i++) 
    {
        pktype = (pktype_e)((pktype_cmp >> (i * PKEY_COMB_TYPE_SHIFT)) & PKEY_COMB_TYPE_MASK);
        //TODO: remove this check eventually 
        if (pktype != pktop->pkfull_list[i]->pkinfo->pktype)
        {
            LOGE("%s(): This should never happen. PK type mismatch toplevel=%d != key_level=%d\n", 
                   __func__, pktype, pktop->pkfull_list[i]->pkinfo->pktype); 
            return FALSE; 
        }

        if( pkey_can_do(pktype, pktype_cmp) ) 
            goto success;  
    }
    return FALSE;  // No keys match 

success: 
    return TRUE;   // At least one key matches 
}


/* ---------------------------------------------------------------------------
  *   Check if a key supports an algporithm 
 * ---------------------------------------------------------------------------*/
int mbed_pk_can_do( mbed_pktop_t *pktop_ref, hybpk_t combtype_cmp)
{
    pktop_t    *pktop = (pktop_t*)pktop_ref;   // top level key info  
    hybpk_t  combtype;                      // combined type all keys     
    pktype_e    pktype, pktype_cmp;
    int         i;
  

    /*---------------------Code ----------------------------------------------*/
    combtype = pktop->hybpk_alg; 

    //  Check the pktype for each each key 
    for (i=0; i < pktop->num_keys; i++) 
    {
        pktype_cmp = (pktype_e)((combtype_cmp >> (i * PKEY_COMB_TYPE_SHIFT)) & PKEY_COMB_TYPE_MASK);
        pktype     = (pktype_e)((combtype     >> (i * PKEY_COMB_TYPE_SHIFT)) & PKEY_COMB_TYPE_MASK);

        if( pkey_can_do(pktype, pktype_cmp) == FALSE)             
            return FALSE; // mismatch 
    }
    return TRUE;  // All keys match
}


/* ---------------------------------------------------------------------------
  *   Get the length of the signature for the toplevel key  
 * ---------------------------------------------------------------------------*/
size_t mbed_pk_get_hybrid_len( mbed_pktop_t *pktop_ref)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    if (pktop == NULL)
        return 0; 
    return pktop->hyb_len; 
}


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Legacy stuff ---------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
mbedtls_ecp_keypair *mbed_get_eckey_ctx ( mbed_pktop_t *pktop_ref)
{
    pktop_t         *pktop = (pktop_t*)pktop_ref;   // top level key info  
    pk_keyparams_t  *kparms; 
    pkfull_t        *pkfull; 
    int              i; 
  
    /*---------------------Code ----------------------------------------------*/
    //  Check the pktype for each each key to see if it match the eckey 
    for (i=0; i < pktop->num_keys; i++) 
    {
        pkfull = pktop->pkfull_list[i];
        kparms = pkfull->pkinfo->get_keyparams( pkfull->pkctx); 
        if( strcmp(kparms->name,"EC") == 0) 
            return  (mbedtls_ecp_keypair*)pkfull->pkctx; 
    }
    return NULL; 
}


/* ---------------------------------------------------------------------------
 *   Access the PK type (should be deprecated) 
 * ---------------------------------------------------------------------------*/
hybpk_t mbed_pk_get_type_old( mbed_pktop_t *pktop_ref)
{
    pktype_e pktype; 
    mbed_pk_get_type(pktop_ref, 0, &pktype); 
    return (hybpk_t)pktype; 
}


/* ---------------------------------------------------------------------------
 *   Access the PK type
 * ---------------------------------------------------------------------------*/
void *mbed_pk_get_pkctx_old( mbed_pktop_t *pktop_ref)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  

    LOGE("%s(): Use of this function is unlikely to work !!!!!\n",__func__); fflush(stdout); 
    if (pktop == NULL || pktop->num_keys == 0)
        return NULL; 
    return  pktop->pkfull_list[0]->pkctx;
}

mbedtls_ecp_keypair *mbedtls_pk_ec(mbed_pktop_t *pktop_ref)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  

    if (pktop == NULL || pktop->num_keys == 0)
        return NULL; 
    printf("%s(): Use of this function is unlikley to work !!!!!\n",__func__); fflush(stdout); 
    return  (mbedtls_ecp_keypair*)pktop->pkfull_list[0]->pkctx;
}

mbedtls_rsa_context *mbedtls_pk_rsa(mbed_pktop_t *pktop_ref)
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  

    if (pktop == NULL || pktop->num_keys == 0)
        return NULL; 
    printf("%s(): Use of this function is unlikley to work !!!!!\n",__func__); fflush(stdout); 
    return  (mbedtls_rsa_context*)pktop->pkfull_list[0]->pkctx;
}

int mbedtls_pk_setup( mbed_pktop_t *pktop_ref, hybpk_t hybpk_alg)
{
    int              rc=-1; 
    (void) pktop_ref; 
    (void) hybpk_alg; 

    /*---------------------Code ----------------------------------------------*/
    LOGD("%s() this function does not work !!!!!\n", __func__); 
    return rc; 
}

size_t mbedtls_pk_get_bitlen (mbed_pktop_t *pktop_ref )
{
    pktop_t   *pktop = (pktop_t*)pktop_ref;   // top level key info  
    size_t     bitlen; 
    if (pktop == NULL || pktop->num_keys == 0)
        return 0;
    mbed_pk_get_bitlen_single(pktop_ref, 0, &bitlen);
    return bitlen; 
}



int mbedtls_pk_can_do( mbed_pktop_t *pktop_ref, hybpk_t  hybpk_alg) {
    return mbed_pk_can_do(pktop_ref,  hybpk_alg); 
}

int mbedtls_pk_sign_restartable( mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, size_t hash_len,  
                                 unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, mbedtls_pk_restart_ctx *rs_ctx )
{
    (void)f_rng; 
    (void)p_rng; 
    return mbed_pk_sign_restartable(pktop_ref,  md_alg, hash , hash_len, sig, sig_size, sig_len, rs_ctx);
}
int mbedtls_pk_sign( mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, size_t hash_len,  
                     unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    (void)f_rng; 
    (void)p_rng; 
    return mbed_pk_sign_restartable(pktop_ref,  md_alg, hash , hash_len, sig, sig_size,sig_len, NULL);
}
int mbedtls_pk_verify_restartable( mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, 
                                   size_t hash_len, const unsigned char *sig, size_t sig_len, mbedtls_pk_restart_ctx *rs_ctx ) {
    return mbed_pk_verify_restartable(pktop_ref,  md_alg, hash , hash_len, sig, sig_len, rs_ctx);
}
int mbedtls_pk_verify(mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len) {
    return mbed_pk_verify_restartable(pktop_ref,  md_alg, hash , hash_len, sig, sig_len, NULL);
}
int mbedtls_pk_verify_ext( mbed_hybpk_t pktype, const void *options, mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, 
                           const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len ) {
    return mbed_pk_verify_ext( pktop_ref, pktype, md_alg, hash, hash_len, sig, sig_len, options);
}


int mbedtls_pk_encrypt( mbed_pktop_t *pktop_ref, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    (void)f_rng; 
    (void)p_rng; 
    return mbed_pk_encap( pktop_ref, MBED_CAPMODE_PKCS1_5,  input, ilen, output, osize, olen); 
}
int mbedtls_pk_decrypt( mbed_pktop_t *pktop_ref, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    (void)f_rng; 
    (void)p_rng; 
    return mbed_pk_decap( pktop_ref, MBED_CAPMODE_PKCS1_5, input, ilen, output, osize, olen); 
}
int mbedtls_pk_check_pair( mbed_pktop_t *pktop_pub, mbed_pktop_t *pktop_prv, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    (void)f_rng; 
    (void)p_rng; 
    return mbed_pk_check_pair(pktop_pub, pktop_prv);
}
int mbedtls_pk_parse_key(mbed_pktop_t *pktop_ref, const unsigned char *key, size_t keylen,  const unsigned char *pwd, size_t pwdlen,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
    (void)f_rng;
    (void)p_rng;
    return mbed_pk_parse_prvkey(pktop_ref, key, keylen, pwd, pwdlen);
}
int mbedtls_pk_parse_keyfile(mbed_pktop_t *pktop_ref, const char *path, const char *pwd, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    (void)f_rng;
    (void)p_rng;
    return mbed_pk_parse_prv_keyfile(pktop_ref, path, pwd);
}
int mbedtls_pk_parse_public_key(mbed_pktop_t *pktop_ref, const unsigned char *key, size_t keylen) {
    return mbed_pk_parse_pubkey(pktop_ref, key, keylen);
}
int mbedtls_pk_parse_public_keyfile(mbed_pktop_t *pktop_ref, const char *path) {
    return mbed_pk_parse_pub_keyfile(pktop_ref, path);
}
int mbedtls_pk_write_key_der(mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size) {
    return mbed_pk_write_key_der(pktop_ref, buf, size);
}
int mbedtls_pk_write_pubkey_der(mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size) {
    return mbedtls_pk_write_pubkey_der(pktop_ref, buf, size);
}
int mbedtls_pk_write_key_pem(mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size) {
    return mbedtls_pk_write_key_pem(pktop_ref, buf, size);
}

int mbedtls_pk_write_pubkey_pem(mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size) {
    return mbedtls_pk_write_pubkey_pem(pktop_ref, buf, size);
}

const char* mbedtls_pk_get_name(mbed_pktop_t *pktop_ref) {
    return mbed_pk_get_hybrid_name(pktop_ref);
}

#endif /* MBEDTLS_PK_C */ 
