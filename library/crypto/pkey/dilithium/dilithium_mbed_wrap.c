#include "common.h"

#if defined(MBEDTLS_PK_C)
#if defined(MBEDTLS_DILITHIUM_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "dilithium_mbed_wrap.h"
#include "pkpq.h"
#include "config.h"
#include "sign.h"

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#include "crypto_util.h"

#define LOGS_PREFIX "    PK_DILITHIUM: "
#include "crypto_common.h"


#if defined(MBEDTLS_PLATFORM_C)
  #include "mbedtls/platform.h"
#endif


//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
// #define OPENSSL_FORMATTED_DUMP

#define ASN1_CHK_ADD(g, f)              \
    do                                  \
    {                                   \
        if( ( rc = (f) ) < 0 )          \
            goto fail;                  \
        else                            \
            (g) += rc;                  \
    } while( 0 )


//----------------------------------------------------------------------------
//----------------- Constant variables ---------------------------------------
//----------------------------------------------------------------------------
// ifdef  KEM_REWORK
const char oid_data[] = MBEDTLS_OID_DILITHIUM_ALG;   // TODO: Fake dilithium oid 
pkbuf_t     dil_oid = {(uint8_t*)oid_data, (uint8_t*)oid_data, sizeof(MBEDTLS_OID_DILITHIUM_ALG)-1, 0}; 


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Local Functions ------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/* ---------------------------------------------------------------------------
 * Dilithium  key clean key context  
 * ---------------------------------------------------------------------------*/
static void *dilkey_clean( void *pkctx )
{
    dilkey_t *dilkey = (dilkey_t*)pkctx; 

    if (dilkey != NULL )
    {
        dilkey->pk = mbed_free(  dilkey->pk );
        if ( dilkey->sk != NULL)
            mbedtls_platform_zeroize( dilkey->sk, dilkey->sk_len); 
        dilkey->sk = mbed_free(  dilkey->sk );
    }
    memset(dilkey, 0, sizeof(dilkey_t)); 
    return NULL;
}


/* ---------------------------------------------------------------------------
 * Dilithium  key set teh dilithium mode   
 * ---------------------------------------------------------------------------*/
static int dilkey_set_dilithium_mode( dilkey_t *dilkey, int level)
{
    struct pk_keyparams_s *kparms; 
    size_t                 pk_len, sk_len, siglen; 

    if ( level == MBED_NIST_LEVEL_2)  
    {
        pk_len  = MBED_DILITHIUM_2_LENGTH_PUBLIC_KEY;
        sk_len  = MBED_DILITHIUM_2_LENGTH_SECRET_KEY;
        siglen = MBED_DILITHIUM_2_LENGTH_SIGNATURE;
    }
    else if (level == MBED_NIST_LEVEL_3 )
    {
        pk_len  = MBED_DILITHIUM_3_LENGTH_PUBLIC_KEY;
        sk_len  = MBED_DILITHIUM_3_LENGTH_SECRET_KEY;
        siglen = MBED_DILITHIUM_3_LENGTH_SIGNATURE;
    }
    else if ( level == MBED_NIST_LEVEL_5 )
    {
        pk_len  = MBED_DILITHIUM_5_LENGTH_PUBLIC_KEY;
        sk_len  = MBED_DILITHIUM_5_LENGTH_SECRET_KEY;
        siglen = MBED_DILITHIUM_5_LENGTH_SIGNATURE;
    }
    else 
        return MBEDTLS_ERR_PK_INVALID_ALG;

    // Check size imported keys 
    if (dilkey->pk_len != 0 && dilkey->pk_len != pk_len)
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    if (dilkey->sk_len != 0 && dilkey->sk_len != sk_len)
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;

    dilkey->pk_len                = pk_len;
    dilkey->sk_len                = sk_len;

    kparms = (struct pk_keyparams_s *)&dilkey->key_params; 
    kparms->pk_len     = pk_len;  
    kparms->sk_len     = sk_len; 
    kparms->sig_len    = siglen;
    kparms->nist_level = level; 
    kparms->name       = "DILITHIUM"; 
    memcpy( &kparms->oid, &dil_oid, sizeof(pkbuf_t)); 


    ((struct pkfull_s *)(dilkey->pkfull))->nist_level = level; // Make the NIST level available on the full level 
    return 0; 
}


 /******************************************************************************
  * Description: Parse a SEC1 encoded private EC key
  *
  * Arguments:   pk       - public key data 
  *              pk_len   - public key length
  *              sk       - secret key data 
  *              sk_len   - secret key length
  *
  * result:      SUCCESS=0 / FAILURE
  *****************************************************************************/
static size_t dilkey_check_pair( uint8_t *sk, uint8_t *pk, size_t siglen)   // TODO fix hardcoded signature 
{
    char     *m = "test message"; 
    uint8_t   sig[ siglen]; 
    size_t    sig_olen;
    int       rc; 

    /*---------------------Code ----------------------------------------------*/
    // Generate the signature  
    //sig_olen = siglen; 
    if( (rc = DILITHIUM_NAMESPACE(signature)( sig, &sig_olen, (const uint8_t*)m, strlen(m), sk)) != 0) 
        goto fail_sign; 
    // Verify the signature  
    if( (rc = DILITHIUM_NAMESPACE(verify)( sig, sig_olen, (const uint8_t*)m, strlen(m), pk)) != 0) 
        goto fail_verify; 

    return 0; 

    // --- Error handling ---
fail_sign:
fail_verify:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT; 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/******************************************************************************
 * Description: Parse a SEC1 encoded private EC key
 *
 * Arguments:   dilkey    - EC key context 
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static size_t asn1_read_octet_string( uint8_t **p, uint8_t *end, uint8_t *obuf, size_t buf_size)
{
    uint8_t  *start = *p; 
    size_t    tag_len; 
    int       rc; 


    /*---------------------Code ----------------------------------------------*/
    if( ( rc = mbedtls_asn1_get_tag( p, end, &tag_len, MBEDTLS_ASN1_OCTET_STRING ) ) != SUCCESS )
        goto fail_invalid_format; 

    if (tag_len > buf_size)
        goto fail_bufsz; 
    memcpy( obuf, *p, tag_len);
    *p += tag_len; 
    return (size_t)(*p-start); 

fail_bufsz: 
    rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; goto fail; 
fail_invalid_format: 
    rc = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc); 
fail:
    return rc; 
}


/******************************************************************************
 * Description: Allocate memory for and read an ASN1 octet string 
 *
 * Arguments:   p     - address of the ASN1 data pointer (ptr moves to after octet string)
 *              end   - pointer to the end of the ASN1 data
 *              obuf  - address of the octet data pointer
 *              olen  - container for the octet length 
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static size_t asn1_malloc_and_read_octet_string( uint8_t **p, uint8_t *end, uint8_t **obuf, size_t *olen)
{
    uint8_t  *tmp = *p; 
    int       rc;

    /*---------------------Code ----------------------------------------------*/
    // --- Read the ASN1 tag length
    if (*obuf != NULL)    // should never happen 
        goto fail_internal; 

    // -- read the length of the octet string 
    if ((rc = mbedtls_asn1_get_tag( &tmp, end, olen, MBEDTLS_ASN1_OCTET_STRING )) != SUCCESS)
        goto fail_invalid_format; 

    // Sanity check on the length
    if (*olen > 65536)
        goto fail_invalid_format; 
    if ((*obuf = mbedtls_calloc( 1, *olen )) == NULL)
        goto fail_malloc; 

    // ---  Octet buffer is allocated, so we can read the ASN1 data 
    return asn1_read_octet_string(p, end, *obuf, *olen);  


    // --- Error handling --- 
fail_internal:
    rc = MBEDTLS_ERR_PK_INTERNAL_ERROR; goto fail; 
fail_malloc:
    rc = MBEDTLS_ERR_PK_ALLOC_FAILED; goto fail; 
fail_invalid_format: 
    rc = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc); 
fail:
    *olen = 0; 
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    return rc; 
}


/******************************************************************************
 * Description: Parse a PKCS8 encoded private dilithium key
 *
 * Arguments:   dilkey   - dilithium key context 
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int dilkey_parse_seckey_der_pkcs8( dilkey_t *dilkey, const uint8_t *key, size_t klen, size_t *der_olen)
{
    uint8_t          *p = (uint8_t *)key;
    uint8_t          *end = p + klen;
    uint8_t          *start = p; 
    size_t            len;
    int               version, rc;
    
        
    /*---------------------Code ----------------------------------------------*/
    /* PrivateKey ::= SEQUENCE {
    *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    *      privateKey     OCTET STRING,
    *      publicKey      OCTET STRING,
    *
    *    Version ::= INTEGER
    *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    *    PrivateKey ::= OCTET STRING
    */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != SUCCESS )
        goto fail_invalid_format;

    end = p + len; 
    SET_VAL_SAFE( der_olen, (size_t)(p - key) + len);  // Set the size of the DER key 

    if( ( rc = mbedtls_asn1_get_int( &p, end, &version ) ) != SUCCESS)
        goto fail_invalid_format;
    if( version != 1 )
        goto fail_invalid_version; 

    // Read the private key 
    if ((rc = asn1_malloc_and_read_octet_string( &p, end, &dilkey->sk, &dilkey->sk_len)) < 0)
        goto fail;

    // Read the public key 
    if ((rc = asn1_malloc_and_read_octet_string( &p, end, &dilkey->pk, &dilkey->pk_len  )) < 0)
        goto fail;

    SET_VAL_SAFE( der_olen ,(size_t)(p - start)); 
    return SUCCESS;


     // --- Error handling --- 
fail_invalid_format:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT; goto fail;
fail_invalid_version:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_VERSION; goto fail; 
fail: 
    dilkey_clean( dilkey );      // cleanup any allocated data
    SET_VAL_SAFE( der_olen, 0);  // Set the size of the DER key 
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    return rc;       
}


/******************************************************************************
 * Description: Parse a DER encoded public key
 *
 * Arguments:   dilkey   - dilithium key context 
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int dilkey_parse_pubkey_der( dilkey_t *dilkey, const uint8_t *key, size_t klen, size_t *der_olen)
{
    uint8_t          *p = (uint8_t *) key;
    uint8_t          *end;
    int               rc;
    
    /*---------------------Code ----------------------------------------------*/
    /*  PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier (Already removed)
    *   
    *   publicKey      OCTET STRING,
    */
    end = p + klen; 

    // --- Read the public key 
    if ((rc = asn1_malloc_and_read_octet_string( &p, end, &dilkey->pk, &dilkey->pk_len  )) < 0)
        goto fail;

    SET_VAL_SAFE( der_olen, rc);  // Set the size of the DER key  
    return SUCCESS;

     // --- Error handling --- 
fail:
    SET_VAL_SAFE( der_olen, 0);  // Set the size of the DER key 
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    return rc;       
}


/* ---------------------------------------------------------------------------
 * Export the EC key in PKCS8 DER format   
 * ---------------------------------------------------------------------------*/
int dilkey_export_seckey_der_pkcs8( dilkey_t *dilkey,  pkbuf_t *odata)
{
    uint8_t     *p;      // active pointer in the DER buffer 
    uint8_t     *start;  // Start of the buffer 
    size_t       osize, len = 0;
    const char  *oid;
    size_t       oid_len;
    int          version, rc;


    /*---------------------Code ----------------------------------------------*/
    pkbuf_extract(odata, &start, &osize, &len); 
    p = start + osize;
    
    /* PrivateKey ::= SEQUENCE {
    *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    *      privateKey     OCTET STRING,
    *      publicKey      OCTET STRING,
    *
    *    Version ::= INTEGER
    *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    *    PrivateKey ::= OCTET STRING
    */
    // --- Write the public key 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string( &p, start, dilkey->pk, dilkey->pk_len));
    
    // --- Write the secret key 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string( &p, start, dilkey->sk, dilkey->sk_len));
    
    // --- version  = 1 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, start, 1));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    // --- Write Private octet string len and tag 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_OCTET_STRING));
    
    // Write PK algorithm OID: Use the hardcoded oid data 
    oid     = (const char*)dil_oid.buf;
    oid_len = dil_oid.size;
    ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&p, start, oid, oid_len, 0));

    // Write version 
    version = 0; 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, start, version));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    odata->iolen = len; 
    return SUCCESS; 

    // --- Error handling ---
fail: 
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    mbedtls_platform_zeroize( (void*)odata->buf, odata->size);
    odata->iolen = 0; 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * Export the dilithium pubkey key in DER format   
 * ---------------------------------------------------------------------------*/
int dilkey_export_pubkey_der( dilkey_t *dilkey,  pkbuf_t *odata)
{
    uint8_t     *p;      // active pointer in the buffer 
    uint8_t     *start;  // Start of the buffer 
    const char  *oid;
    size_t       len = 0, oid_len;
    int          rc;


    /*---------------------Code ----------------------------------------------*/
    start = (uint8_t*)odata->buf; 
    p = start + odata->size;   // Start at the end of the buffer and write backwards 

    /*
    *    PublicKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    *    PublicKey ::= OCTET STRING
    */
    // --- write the pubkey 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string( &p, start, dilkey->pk, dilkey->pk_len));

     
    /*  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */ 
    // --- TODO the bit string is technically not needed 
    *--p = 0;
    len += 1;
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_BIT_STRING)); 

    // Write PK algorithm OID: Use the hardcoded oid data 
    oid     = (const char*)dil_oid.buf;
    oid_len = dil_oid.size;    
    ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&p, start, oid, oid_len, 0));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    odata->iolen = len; 

    return SUCCESS; 

    // --- Error handling ---
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    mbedtls_platform_zeroize((void*)odata->buf, odata->size);
    odata->iolen = 0; 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * Export the dilithium pubkey key in DER format   
 * ---------------------------------------------------------------------------*/
int dilkey_export_pubkey_ssl( dilkey_t *dilkey, pktarget_e target, pkbuf_t *odata)
{
    (void) dilkey;
    (void) odata;
    (void) target; 

    printf("%s(): not implemented yet\n",__func__); 
    return 0;
}

/******************************************************************************
 * Description: Export the key information to a text buffer in readable format 
 *
 * Arguments:   rsakey   - rsakey key context 
 *              target   - public or private key 
 *              level    - export detail level  
 *              result   - container for the resulting text  
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int dilkey_export_key_text(dilkey_t *dilkey, pktarget_e target, pkexport_e level, pkbuf_t *result)
{
    pkbuf_t         odata;  // Make a working copy that can be modified
    pk_keyparams_t *kparms;
    size_t          olen;
    int             dump_full = 0; 

    /*---------------------Code ----------------------------------------------*/
    pkbuf_init( &odata, result->buf, result->size, result->iolen); 
    *(uint8_t*)(odata.buf + odata.size - 1) = 0;              // Null terminate, just in case

    kparms = &dilkey->key_params;
    if (target == PK_TARGET_PRV)
    {
        olen = snprintf( (char *)odata.buf, odata.size, "Dilithium Private-Key: (mode=%d) (sk=%d, pk=%d, sig=%d)\n", 
                         kparms->nist_level, (int)kparms->sk_len, (int)kparms->pk_len, (int)kparms->sig_len  );
    }
    else
    {
        olen = snprintf( (char *)odata.buf, odata.size, "Dilithium Public-Key:(mode=%d) (pk=%d, sig=%d)\n", 
                         kparms->nist_level, (int)kparms->pk_len, (int)kparms->sig_len  );
    }
    pkbuf_move(&odata, olen);

    if ( level == PK_EXPORT_FULL)
        dump_full = TRUE;

    if (target == PK_TARGET_PRV)
    {
      #ifdef OPENSSL_FORMATTED_DUMP
        olen = util_dump2buf(dilkey->sk, dilkey->sk_len, ':', 15, &odata, "prv",dump_full);
      #else 
        olen = util_dump2buf(dilkey->sk, dilkey->sk_len, ' ', 32, &odata, "prv",dump_full);
      #endif 
        pkbuf_move( &odata, olen);
    }
  #ifdef OPENSSL_FORMATTED_DUMP
    olen = util_dump2buf(dilkey->pk, dilkey->pk_len, ':', 15, &odata, "pub",dump_full);
  #else 
    olen = util_dump2buf(dilkey->pk, dilkey->pk_len, ' ', 32, &odata, "pub",dump_full);
  #endif 
    pkbuf_move( &odata, olen);

    // Update the length of the data written
    result->iolen = pkbuf_total_io(&odata); 
    return result->iolen;
}


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Dilithium wrapper Functions ------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
  * Description: get the key paramater info 
  *
  * Arguments:   pkctx    - Dilithium key context 
  *
  * result:      pointer to the key paramaters structure 
  *****************************************************************************/
static pk_keyparams_t *dilkey_get_keyparams_wrap( void *pkctx)  
{
    return &((dilkey_t *)pkctx)->key_params;
}

/* ---------------------------------------------------------------------------
 * EC get bitlen wrapper  
 * ---------------------------------------------------------------------------*/
//static int dilkey_get_bitlen( void *pkctx, size_t *bitlen)
//{
//    *bitlen = ((dilkey_t *)pkctx)->sig_len*8; 
//    return SUCCESS;
//}

/* ---------------------------------------------------------------------------
 * EC key verify signature wrapper 
 * ---------------------------------------------------------------------------*/
static int dilkey_vrfy_wrap(void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig, void *rs_ctx)
{    
    dilkey_t  *dilkey = (dilkey_t *)pkctx;
    size_t     siglen; 
    int        rc; 
    (void)md_alg; // The current delithium code hashes it again 
    (void)rs_ctx;

    /*---------------------Code ----------------------------------------------*/
    siglen = dilkey->key_params.sig_len;
    if (sig->size < siglen)
        goto fail_bad_data;

    // pqcrystals_dilithium3_ref_verify()
    if(( rc = DILITHIUM_NAMESPACE( verify)(sig->buf, siglen, hash->buf, hash->size, dilkey->pk)) != 0) 
            goto fail; 

    // --- Note: a hybrid signature could be larger than the dilithium signature (siglen < sig->size)
    // --- As a result, it is normal that not all bytes are consumed/used 
    
    sig->iolen = siglen;  // Return the number of bytes in the signature 
    return SUCCESS;


    // --- Error handling --- 
fail_bad_data: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    sig->iolen = 0;
    return rc; 
}


/* ---------------------------------------------------------------------------
 * Dilithium key create signature, wrapper function
 * ---------------------------------------------------------------------------*/
static int dilkey_sign_wrap( void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig_out, void *rs_ctx) 
{
    dilkey_t   *dilkey = (dilkey_t *)pkctx;
    size_t      siglen, sig_olen;
    int         rc; 
    (void) md_alg; // The current delithium code hashes it again 
    (void) rs_ctx;

    /*---------------------Code ----------------------------------------------*/
    siglen = dilkey->key_params.sig_len;
    if (sig_out->size  < siglen)
        goto fail_bufsz; 

    // pqcrystals_dilithium3_ref_signature
    if(( rc = DILITHIUM_NAMESPACE(signature)((uint8_t*)sig_out->buf, &sig_olen, hash->buf, hash->size, dilkey->sk)) != 0) 
    {
        goto fail; 
    }
    printf( "%s(): sigout_len = %d, siglen = %d\n", __func__, (int)sig_olen, (int)siglen); 
    sig_out->iolen = sig_olen;
    return SUCCESS; 


    // --- Error handling --- 
fail_bufsz: 
    rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; goto fail;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    sig_out->iolen = 0; 
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 * EC keygen wrapper 
 * ---------------------------------------------------------------------------*/
static int dilkey_keygen_wrap(void *pkctx, char* keygen_params)
{
    dilkey_t     *dilkey = (dilkey_t*)pkctx;
    rnginfo_t    *rng; 
    char         *rest, *token;
    nistlevel_e   nist_level; 
    int           rc; 


    /*---------------------Code ----------------------------------------------*/
    // parse the keygen_params
    rest       = keygen_params; 
    nist_level = MBED_NIST_LEVEL_3;          // default security level 

    LOGD("%s() keygen_params=%s\n", __func__, keygen_params);
    while ((token = strtok_r( rest, ":", &rest )))
    {
        // LOGD( "%s\n", token );
        if (strncmp( token, "level=", 6 ) == 0)
            nist_level = (nistlevel_e)atoi(token + 6);
        else 
            goto fail_bad_input;
    }
    //if (nist_level != 2 && nist_level != 3 && nist_level != 5 )
    if ( nist_level != 3 )  // TODO: suport other nist levels 
        goto fail_bad_input;

    if ( nist_level == MBED_NIST_LEVEL_3 )
        dilkey_set_dilithium_mode(dilkey, nist_level); 
    else 
        goto fail; 

    dilkey->pk = mbed_calloc(1, dilkey->pk_len);
    dilkey->sk = mbed_calloc(1, dilkey->sk_len);

    // Generate the key pair 
    if ((rc = pkey_get_rng_info( (pktop_t *)dilkey->pktop, &rng )) != SUCCESS)
        goto fail;

    // TODO pass in the RNG info 
    rc = DILITHIUM_NAMESPACE( keypair )( dilkey->pk, dilkey->sk, rng->cb, rng->ctx);
    if ( rc != 0) 
        goto fail_keygen; 

    if( (rc = dilkey_check_pair( dilkey->sk, dilkey->pk, dilkey->key_params.sig_len)) != 0) 
        goto fail; 
    return 0; 

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA; goto fail; 
fail_keygen: 
    rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT; 
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc;
}

/* ---------------------------------------------------------------------------
 * EC key check public/private key match 
 * ---------------------------------------------------------------------------*/
static int dilkey_check_pair_wrap( void *pkctx_pub, void *pkctx_prv)
{
    const dilkey_t  *dilkey_pub = (dilkey_t *)pkctx_pub;
    const dilkey_t  *dilkey_prv = (dilkey_t *)pkctx_prv;
    int             rc; 

    /*---------------------Code ----------------------------------------------*/
    if ((rc = dilkey_check_pair( dilkey_prv->sk, dilkey_pub->pk, dilkey_pub->key_params.sig_len )) != SUCCESS)
        goto fail;
    return SUCCESS;

    // --- Error handling --- 
fail:  
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc;
}


/* ---------------------------------------------------------------------------
 * EC key alloc key context function  
 * ---------------------------------------------------------------------------*/
static void* dilkey_alloc_wrap(pkfull_t *pkfull)
{
    dilkey_t *dilkey;

    /*---------------------Code ----------------------------------------------*/
    dilkey = (dilkey_t *)mbedtls_calloc(1, sizeof(dilkey_t));  
    dilkey->pkfull = (void *)pkfull;         // Reference back to the full level 
    dilkey->pktop  = (void *)pkfull->pktop;  // Reference back to the top level
    return dilkey; 
}

/* ---------------------------------------------------------------------------
 * EC key free key context function  
 * ---------------------------------------------------------------------------*/
static void *dilkey_free_wrap( void *pkctx )
{
    dilkey_t *dilkey = (dilkey_t*)pkctx; 

    dilkey_clean( dilkey);
    dilkey = mbed_free( dilkey );
    return NULL;
}


/* ---------------------------------------------------------------------------
 * Wrapper import EC key in DER format 
 * ---------------------------------------------------------------------------*/
static int dilkey_import_wrap( void *pkctx, pktarget_e target, pkbuf_t *idata, void *alg_info, size_t *der_olen) 
{
   dilkey_t  *dilkey = (dilkey_t*)pkctx; 
   int        level, rc = 0;
   (void) alg_info; 


   /*---------------------Code ----------------------------------------------*/
   if (( target == PK_TARGET_PUBSSL) || ( target == PK_TARGET_PUBSSL_RESP)) 
   {
       printf("!!!!!!!!!!!!!! %s(): PK_TARGET_PUBSSL and PK_TARGET_PUBSSL_RESP not supported yet!!!!!!",__func__);
       rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
       goto fail;
   }
   else 
   {
       if (target == PK_TARGET_PRV)
           rc = dilkey_parse_seckey_der_pkcs8( dilkey, idata->buf, idata->size, der_olen );
       else if (target == PK_TARGET_PUB)
           rc = dilkey_parse_pubkey_der( dilkey, idata->buf, idata->size, der_olen); 
       else 
           rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
   }
   if (rc != SUCCESS)
       goto fail;   

   // --- Find out the Dilithium level based of the key lengths
   if (dilkey->pk_len == MBED_DILITHIUM_2_LENGTH_PUBLIC_KEY)
       level = MBED_NIST_LEVEL_2;
   else if (dilkey->pk_len == MBED_DILITHIUM_3_LENGTH_PUBLIC_KEY)
       level = MBED_NIST_LEVEL_3;
   else if (dilkey->pk_len == MBED_DILITHIUM_5_LENGTH_PUBLIC_KEY)
       level = MBED_NIST_LEVEL_5;
   else 
       goto fail_mode; 

   if( (rc = dilkey_set_dilithium_mode ( dilkey, level)) != 0) 
       goto fail; 

   if (target == PK_TARGET_PRV)
   {
       if( ( rc = dilkey_check_pair( dilkey->sk, dilkey->pk, dilkey->key_params.sig_len)) != 0 )
           goto fail_invalid_format;
   }
   LOGD("%s(): Found dilithium level (nist_level) = %d\n", __func__, dilkey->key_params.nist_level);
   return rc;
    
    // --- Error handling --- 
fail_invalid_format: 
   rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
fail_mode: 
   rc = MBEDTLS_ERR_PK_INVALID_ALG;
fail:
    dilkey_clean( dilkey);
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * Wrapper export EC key 
 * export format: 0 is DER, 1=BASIC, 2=EXTENDED, 3=FULL 
 * return:  Minimum size of buffer required or buf  
 * ---------------------------------------------------------------------------*/
static int dilkey_export_wrap( void *pkctx, pktarget_e target, pkexport_e level, pkbuf_t *result) 
{
    dilkey_t  *dilkey = (dilkey_t*)pkctx; 
    int       rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( level == PK_EXPORT_DER)
    {
        if (target == PK_TARGET_PRV)
            rc = dilkey_export_seckey_der_pkcs8(dilkey, result);
        else if (target == PK_TARGET_PUB)
            rc = dilkey_export_pubkey_der(dilkey, result);
        else if ((target == PK_TARGET_PUBSSL) || (target == PK_TARGET_PUBSSL_RESP)) 
            rc = dilkey_export_pubkey_ssl(dilkey, target, result);
        else 
            rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    }
    else 
    {
        rc = dilkey_export_key_text( dilkey, target, level, result );
    }
    if (rc < 0)
        goto fail; 
    return SUCCESS; 

    // --- Error handling --- 
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * EC key debug function  
 * ---------------------------------------------------------------------------*/
static void dilkey_debug_wrap( void *pkctx, mbedtls_pk_debug_item *items )
{
    (void) pkctx; 
    items->type = MBEDTLS_PK_DEBUG_DILITH;
    items->name = "dilith_pk";
   //  items->value = &( ((mbedtls_ecp_keypair *) ctx)->Q );
}

//----------------------------------------------------------------------------
//----------------- Constants ------------------------------------------------
//----------------------------------------------------------------------------
pkinfo_t dilkey_pkinfo = {
    MBEDTLS_PK_DILITHIUM,
    dilkey_get_keyparams_wrap,
    dilkey_vrfy_wrap,
    dilkey_sign_wrap,             
    NULL,                         // decapsulate not supported  
    NULL,                         // encapsulate not supported  
    NULL,                         // DH not supported   
    dilkey_keygen_wrap,
    dilkey_check_pair_wrap,
    dilkey_alloc_wrap,       
    dilkey_free_wrap,        
    dilkey_import_wrap,
    dilkey_export_wrap,
    dilkey_debug_wrap
};

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/* ---------------------------------------------------------------------------
 *  Register the algorithm as a constructor 
 * ---------------------------------------------------------------------------*/
// Fixme 
int pkey_dilkey_enable_constructors;  /* not used for anything except for the linker to link the constructor */
void __attribute__ ((constructor)) pkey_dilkey_constructor(void)
{
    pkey_register_pk_algorithm(&dilkey_pkinfo); 
}
#endif /* MBEDTLS_DILITHIUM_C */
#endif /* MBEDTLS_PK_C */
