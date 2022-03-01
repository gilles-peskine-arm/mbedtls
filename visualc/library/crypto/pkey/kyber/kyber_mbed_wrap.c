#include "common.h"

#if defined(MBEDTLS_PK_C)

#include "pkpq.h"

#if defined(MBEDTLS_KYBER_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "kyber_mbed_wrap.h"
#include "indcpa.h"
#include "kem.h"

#include "crypto_util.h"

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#define LOGS_PREFIX "    PK_RSA: "
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
const char kyber_oid_data[] = MBEDTLS_OID_KYBER_ALG;   // TODO: Fake kyber oid 
pkbuf_t    kyb_oid = {(uint8_t*)kyber_oid_data, (uint8_t*)kyber_oid_data, sizeof(MBEDTLS_OID_KYBER_ALG)-1, 0}; 


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Local Functions ------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/* ---------------------------------------------------------------------------
 * Kyber  key clean key context  
 * ---------------------------------------------------------------------------*/
static void *kybkey_clean( void *pkctx )
{
    kybkey_t *kybkey = (kybkey_t*)pkctx; 

    if (kybkey != NULL )
    {
        kybkey->pk = mbed_free(  kybkey->pk );
        if ( kybkey->sk != NULL)
            mbedtls_platform_zeroize( kybkey->sk, kybkey->sk_len); 
        kybkey->sk = mbed_free(  kybkey->sk );
    }
    memset(kybkey, 0, sizeof(kybkey_t)); 
    return NULL;
}


/* ---------------------------------------------------------------------------
 * Kyber  key set teh kyber mode   
 * ---------------------------------------------------------------------------*/
static int kybkey_set_kyber_mode( kybkey_t *kybkey, int level)
{
    struct pk_keyparams_s *kparms; 
    size_t                 pk_len, sk_len, ct_len, ss_len; 

    if ( level == MBED_NIST_LEVEL_2)  
    {
        pk_len  = MBED_PK_KYBER_512_LENGTH_PUBLIC_KEY;
        sk_len  = MBED_PK_KYBER_512_LENGTH_SECRET_KEY;
        ct_len  = MBED_PK_KYBER_512_LENGTH_CIPHERTEXT;
        ss_len  = MBED_PK_KYBER_512_LENGTH_SHARED_SECRET;
    }
    else if (level == MBED_NIST_LEVEL_3 )
    {
        pk_len  = MBED_PK_KYBER_768_LENGTH_PUBLIC_KEY;
        sk_len  = MBED_PK_KYBER_768_LENGTH_SECRET_KEY;
        ct_len  = MBED_PK_KYBER_768_LENGTH_CIPHERTEXT;
        ss_len  = MBED_PK_KYBER_768_LENGTH_SHARED_SECRET;
    }
    else if ( level == MBED_NIST_LEVEL_4 )
    {
        pk_len  = MBED_PK_KYBER_1024_LENGTH_PUBLIC_KEY;
        sk_len  = MBED_PK_KYBER_1024_LENGTH_SECRET_KEY;
        ct_len  = MBED_PK_KYBER_1024_LENGTH_CIPHERTEXT;
        ss_len  = MBED_PK_KYBER_1024_LENGTH_SHARED_SECRET;
    }
    else 
        return MBEDTLS_ERR_PK_INVALID_ALG;

    // Check size imported keys 
    if (kybkey->pk_len != 0 && kybkey->pk_len != pk_len)
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    if (kybkey->sk_len != 0 && kybkey->sk_len != sk_len)
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;

    kybkey->pk_len = pk_len;
    kybkey->sk_len = sk_len;

    kparms = (struct pk_keyparams_s *)&kybkey->key_params; 
    kparms->pk_len     = pk_len;  
    kparms->sk_len     = sk_len; 
    kparms->ct_len     = ct_len;
    kparms->ss_len     = ss_len; 
    kparms->nist_level = level; 
    kparms->name       = "KYBER"; 
    memcpy( &kparms->oid, &kyb_oid, sizeof(pkbuf_t)); 

    ((struct pkfull_s *)(kybkey->pkfull))->nist_level = level; // Make the NIST level available on the full level 
    return 0; 
}


 /******************************************************************************
  * Description: Parse a SEC1 encoded private Kyber key
  *
  * Arguments:   pk       - public key data 
  *              pk_len   - public key length
  *              sk       - secret key data 
  *              sk_len   - secret key length
  *
  * result:      SUCCESS=0 / FAILURE
  *****************************************************************************/
static size_t kybkey_check_pair( kybkey_t *kybkey, uint8_t *sk, uint8_t *pk, size_t ct_len, size_t ss_len)  
{
    uint8_t      ct[ ct_len];          // cipher text  
    uint8_t      m[ ss_len];           // message  
    uint8_t      m_result[ ss_len];    // message after encrypt/decrypt    
    uint8_t      coins[ ss_len];       // coins    
    int          rc; 
    (void) kybkey; 

    /*---------------------Code ----------------------------------------------*/
    // erncapsulate 
    // int indcpa_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    KYBER_NAMESPACE(_indcpa_enc)( ct, m, pk, coins);
    // Decapsulate
    // int indcpa_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    KYBER_NAMESPACE(_indcpa_dec)( m_result, (const uint8_t*)ct, sk);
    if ( memcmp(m, m_result, ss_len) != 0)
        goto fail; 
    return 0; 

    // --- Error handling ---
fail: 
    rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT; 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/******************************************************************************
 * Description: Parse a SEC1 encoded private Kyber key
 *
 * Arguments:   kybkey    - Kyber key context 
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
 * Description: Parse a PKCS8 encoded private kyber key
 *
 * Arguments:   kybkey   - kyber key context 
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int kybkey_parse_seckey_der_pkcs8( kybkey_t *kybkey, const uint8_t *key, size_t klen, size_t *der_olen)
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
    if ((rc = asn1_malloc_and_read_octet_string( &p, end, &kybkey->sk, &kybkey->sk_len)) < 0)
        goto fail;

    // Read the public key 
    if ((rc = asn1_malloc_and_read_octet_string( &p, end, &kybkey->pk, &kybkey->pk_len  )) < 0)
        goto fail;

    SET_VAL_SAFE( der_olen ,(size_t)(p - start)); 
    return SUCCESS;


     // --- Error handling --- 
fail_invalid_format:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT; goto fail;
fail_invalid_version:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_VERSION; goto fail; 
fail: 
    kybkey_clean( kybkey );      // cleanup any allocated data
    SET_VAL_SAFE( der_olen, 0);  // Set the size of the DER key 
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    return rc;       
}


/******************************************************************************
 * Description: Parse a DER encoded public key
 *
 * Arguments:   kybkey   - kyber key context 
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int kybkey_parse_pubkey_der( kybkey_t *kybkey, const uint8_t *key, size_t klen, size_t *der_olen)
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
    if ((rc = asn1_malloc_and_read_octet_string( &p, end, &kybkey->pk, &kybkey->pk_len  )) < 0)
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
 * Export the Kyber key in PKCS8 DER format   
 * ---------------------------------------------------------------------------*/
int kybkey_export_seckey_der_pkcs8( kybkey_t *kybkey,  pkbuf_t *odata)
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
    ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string( &p, start, kybkey->pk, kybkey->pk_len));
    
    // --- Write the secret key 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string( &p, start, kybkey->sk, kybkey->sk_len));
    
    // --- version  = 1 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, start, 1));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    // --- Write Private octet string len and tag 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_OCTET_STRING));
    
    // Write PK algorithm OID: Use the hardcoded oid data 
    oid     = (const char*)kyb_oid.buf;
    oid_len = kyb_oid.size;
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
 * Export the kyber pubkey key in DER format   
 * ---------------------------------------------------------------------------*/
int kybkey_export_pubkey_der( kybkey_t *kybkey,  pkbuf_t *odata)
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
    ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string( &p, start, kybkey->pk, kybkey->pk_len));

     
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
    oid     = (const char*)kyb_oid.buf;
    oid_len = kyb_oid.size;    
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
 * Export the kyber pubkey key in DER format   
 * ---------------------------------------------------------------------------*/
int kybkey_export_pubkey_ssl( kybkey_t *kybkey, pktarget_e target, pkbuf_t *odata)
{
    (void) kybkey;
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
static int kybkey_export_key_text(kybkey_t *kybkey, pktarget_e target, pkexport_e level, pkbuf_t *result)
{
    pkbuf_t         odata;  // Make a working copy that can be modified
    pk_keyparams_t *kparms;
    size_t          olen;
    int             dump_full = 0; 

    /*---------------------Code ----------------------------------------------*/
    pkbuf_init( &odata, result->buf, result->size, result->iolen); 
    *(uint8_t*)(odata.buf + odata.size - 1) = 0;              // Null terminate, just in case

    kparms = &kybkey->key_params;
    if (target == PK_TARGET_PRV)
    {
        olen = snprintf( (char *)odata.buf, odata.size, "Kyber Private-Key: (mode=%d) (sk=%d, pk=%d, ct=%d, ss=%d)\n", 
                         kparms->nist_level, (int)kybkey->sk_len, (int)kybkey->pk_len, (int)kparms->ct_len, (int)kparms->ss_len  );
    }
    else
    {
        olen = snprintf( (char *)odata.buf, odata.size, "Kyber Public-Key:(mode=%d) (pk=%d,  ct=%d, ss=%d)\n", 
                         kparms->nist_level, (int)kybkey->pk_len,  (int)kparms->ct_len, (int)kparms->ss_len);
    }
    pkbuf_move(&odata, olen);

    if ( level == PK_EXPORT_FULL)
        dump_full = TRUE;

    if (target == PK_TARGET_PRV)
    {
      #ifdef OPENSSL_FORMATTED_DUMP
        olen = util_dump2buf(kybkey->sk, kybkey->sk_len, ':', 15, &odata, "prv",dump_full);
      #else 
        olen = util_dump2buf(kybkey->sk, kybkey->sk_len, ' ', 32, &odata, "prv",dump_full);
      #endif 
        pkbuf_move( &odata, olen);
    }
  #ifdef OPENSSL_FORMATTED_DUMP
    olen = util_dump2buf(kybkey->pk, kybkey->pk_len, ':', 15, &odata, "pub",dump_full);
  #else 
    olen = util_dump2buf(kybkey->pk, kybkey->pk_len, ' ', 32, &odata, "pub",dump_full);
  #endif 
    pkbuf_move( &odata, olen);

    // Update the length of the data written
    result->iolen = pkbuf_total_io(&odata); 
    return result->iolen;
}


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Kyber wrapper Functions ----------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/******************************************************************************
  * Description: get the key paramater info 
  *
  * Arguments:   pkctx    - Kyber key context 
  *
  * result:      pointer to the key paramaters structure 
  *****************************************************************************/
static pk_keyparams_t *kybkey_get_keyparams_wrap( void *pkctx)  
{
    return &((kybkey_t *)pkctx)->key_params;
}

/* ---------------------------------------------------------------------------
 * Kyber get bitlen wrapper  
 * ---------------------------------------------------------------------------*/
//static int kybkey_get_bitlen( void *pkctx, size_t *bitlen)
//{
//    *bitlen = ((kybkey_t *)pkctx)->ct_len*8; 
//    return SUCCESS;
//}

/******************************************************************************
 * Description: Kyber key encapsulate a message (shared secret typically)  
 *
 * Arguments:   pkctx    - Kyber key context 
 *              mode     - encapsulation mode (unused)
 *              m        - message(shared secret) to encapsulate
 *              result   - cipher text out 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int kybkey_encap_wrap( void *pkctx, capmode_e mode, pkbuf_t *m,  pkbuf_t *result)
{
    kybkey_t   *kybkey = (kybkey_t *)pkctx;
    rnginfo_t  *rng;  
    uint8_t     coins[32];   // random coins 
    size_t      ct_len, ss_len;  
    int         rc; 
    (void) mode; 


    /*---------------------Code ----------------------------------------------*/
    ct_len = kybkey->key_params.ct_len;     // cipher text length c
    ss_len = kybkey->key_params.ss_len;     // shared secret length 
    if ((result->size < ct_len) || (m->size != ss_len ))
        goto fail_bad_input; 

    if (kybkey->pk == NULL)
        goto fail_bad_input; 

    // --- Get random number generator info from the top context  
    if ((rc = pkey_get_rng_info( (pktop_t *)kybkey->pktop, &rng )) != SUCCESS)
        goto fail;
    // Create random coins 
    if( (rc = rng->cb( rng->ctx, coins, sizeof(coins))) != SUCCESS)
        goto fail; 
    // int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk, ... );
    KYBER_NAMESPACE(_indcpa_enc)( (uint8_t*)result->buf, m->buf, kybkey->pk, coins);

    // --- Set the input/output lengths for the message(shared secret) (IN) and the cipher text (OUT)
    m->iolen      = ss_len;  
    result->iolen = ct_len;
    //util_dump( result->buf, result->iolen, "ciphertext out" );
    return SUCCESS; 


    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    result->iolen = 0; 
    m->iolen      = 0;  
    return rc;                                                                                        
}


/******************************************************************************
 * Description: Kyber key decapsulate a message (shared secret typically)  
 *
 * Arguments:   pkctx    - Kyber key context 
 *              mode     - encapsulation mode (unused)
 *              ct       - cipher text to decapsulate
 *              shared   - shared secret out  
 * 
 * Result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int kybkey_decap_wrap( void *pkctx, capmode_e mode, pkbuf_t *ct,  pkbuf_t *shared)
{
    kybkey_t   *kybkey = (kybkey_t *)pkctx;
    size_t      ct_len, ss_len;  
    int         rc; 
    (void) mode; 

    /*---------------------Code ----------------------------------------------*/
    ct_len = kybkey->key_params.ct_len; 
    ss_len = kybkey->key_params.ss_len;     // shared secret length 
    if ( (ct->size < ct_len) || ( shared->size < ss_len) )
        goto fail_bufsz; 

    if (kybkey->sk == NULL)
        goto fail_bad_input; 

    // int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    KYBER_NAMESPACE(_indcpa_dec)( (uint8_t*)shared->buf, ct->buf, kybkey->sk);

    // util_dump( shared->buf, ss_len, "message out" );
    // --- Set the input/output lengths for the cipher text (IN) and the shared secret (OUT)
    ct->iolen     = ct_len;
    shared->iolen = ss_len;
    return SUCCESS; 

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail;
fail_bufsz: 
    rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; goto fail;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    shared->iolen = 0; 
    ct->iolen     = 0;
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 * Kyber keygen wrapper 
 * ---------------------------------------------------------------------------*/
static int kybkey_keygen_wrap(void *pkctx, char* keygen_params)
{
    kybkey_t     *kybkey = (kybkey_t*)pkctx;
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
    if ( nist_level != 3 )  // TODO: support other nist levels 
        goto fail_bad_input;

    if ( nist_level == MBED_NIST_LEVEL_3 )
        kybkey_set_kyber_mode(kybkey, nist_level); 
    else 
        goto fail; 

    kybkey->pk = mbed_calloc(1, kybkey->pk_len);
    kybkey->sk = mbed_calloc(1, kybkey->sk_len);

    // --- Get random number generator info from the top context  
    if ((rc = pkey_get_rng_info( (pktop_t *)kybkey->pktop, &rng )) != SUCCESS)
        goto fail;

    // --- Generate the key pair 
    rc = KYBER_NAMESPACE(_keypair )( kybkey->pk, kybkey->sk, rng->cb, rng->ctx);
    if ( rc != 0) 
        goto fail_keygen; 

    if( (rc = kybkey_check_pair( kybkey, kybkey->sk, kybkey->pk, kybkey->key_params.ct_len, kybkey->key_params.ss_len)) != 0) 
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
 * Kyber key check public/private key match 
 * ---------------------------------------------------------------------------*/
static int kybkey_check_pair_wrap( void *pkctx_pub, void *pkctx_prv)
{
    const kybkey_t   *kybkey_pub = (kybkey_t *)pkctx_pub;
    const kybkey_t   *kybkey_prv = (kybkey_t *)pkctx_prv;
    pk_keyparams_t   *kparms;
    int               rc; 

    /*---------------------Code ----------------------------------------------*/
    if ((kybkey_pub->pk == NULL) || (kybkey_prv->sk == NULL))
        goto fail_bad_input;    

    // --- use the RNG from the private key 
    kparms = &kybkey_prv->key_params; 
    if ((rc = kybkey_check_pair( pkctx_prv, kybkey_prv->sk, kybkey_pub->pk, kparms->ct_len, kparms->ss_len)) != SUCCESS)
        goto fail;
    return SUCCESS;

    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
fail:  
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc;
}


/* ---------------------------------------------------------------------------
 * Kyber key alloc key context function  
 * ---------------------------------------------------------------------------*/
static void* kybkey_alloc_wrap(pkfull_t *pkfull)
{
    kybkey_t *kybkey;

    /*---------------------Code ----------------------------------------------*/
    kybkey = (kybkey_t *)mbedtls_calloc(1, sizeof(kybkey_t));  
    kybkey->pkfull = (void *)pkfull;         // Reference back to the full level 
    kybkey->pktop  = (void *)pkfull->pktop;  // Reference back to the top level
    return kybkey; 
}

/* ---------------------------------------------------------------------------
 * Kyber key free key context function  
 * ---------------------------------------------------------------------------*/
static void *kybkey_free_wrap( void *pkctx )
{
    kybkey_t *kybkey = (kybkey_t*)pkctx; 

    kybkey_clean( kybkey);
    kybkey = mbed_free( kybkey );
    return NULL;
}


/* ---------------------------------------------------------------------------
 * Wrapper import Kyber key in DER format 
 * ---------------------------------------------------------------------------*/
static int kybkey_import_wrap( void *pkctx, pktarget_e target, pkbuf_t *idata, void *alg_info, size_t *der_olen) 
{
   kybkey_t  *kybkey = (kybkey_t*)pkctx; 
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
           rc = kybkey_parse_seckey_der_pkcs8( kybkey, idata->buf, idata->size, der_olen );
       else if (target == PK_TARGET_PUB)
           rc = kybkey_parse_pubkey_der( kybkey, idata->buf, idata->size, der_olen); 
       else 
           rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
   }
   if (rc != SUCCESS)
       goto fail;   

   // --- Find out the Kyber level based of the key lengths
   if (kybkey->pk_len == MBED_PK_KYBER_512_LENGTH_PUBLIC_KEY)
       level = MBED_NIST_LEVEL_2;
   else if (kybkey->pk_len == MBED_PK_KYBER_768_LENGTH_PUBLIC_KEY)
       level = MBED_NIST_LEVEL_3;
   else if (kybkey->pk_len == MBED_PK_KYBER_1024_LENGTH_PUBLIC_KEY)
       level = MBED_NIST_LEVEL_4;
   else 
       goto fail_mode; 

   if( (rc = kybkey_set_kyber_mode ( kybkey, level)) != 0) 
       goto fail; 

   if (target == PK_TARGET_PRV)
   {
       if( ( rc = kybkey_check_pair( kybkey, kybkey->sk, kybkey->pk, kybkey->key_params.ct_len, kybkey->key_params.ss_len)) != 0 )
           goto fail_invalid_format;
   }
   LOGD("%s(): Found kyber level (nist_level) = %d\n", __func__, kybkey->key_params.nist_level);
   return rc;
    
    // --- Error handling --- 
fail_invalid_format: 
   rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
fail_mode: 
   rc = MBEDTLS_ERR_PK_INVALID_ALG;
fail:
    kybkey_clean( kybkey);
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * Wrapper export Kyber key 
 * export format: 0 is DER, 1=BASIC, 2=EXTENDED, 3=FULL 
 * return:  Minimum size of buffer required or buf  
 * ---------------------------------------------------------------------------*/
static int kybkey_export_wrap( void *pkctx, pktarget_e target, pkexport_e level, pkbuf_t *result) 
{
    kybkey_t  *kybkey = (kybkey_t*)pkctx; 
    int       rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( level == PK_EXPORT_DER)
    {
        if (target == PK_TARGET_PRV)
            rc = kybkey_export_seckey_der_pkcs8(kybkey, result);
        else if (target == PK_TARGET_PUB)
            rc = kybkey_export_pubkey_der(kybkey, result);
        else if ((target == PK_TARGET_PUBSSL) || (target == PK_TARGET_PUBSSL_RESP)) 
            rc = kybkey_export_pubkey_ssl(kybkey, target, result);
        else 
            rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    }
    else 
    {
        rc = kybkey_export_key_text( kybkey, target, level, result );
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
 * Kyber key debug function  
 * ---------------------------------------------------------------------------*/
static void kybkey_debug_wrap( void *pkctx, mbedtls_pk_debug_item *items )
{
    (void) pkctx; 
    items->type = MBEDTLS_PK_DEBUG_DILITH;
    items->name = "kybith_pk";
   //  items->value = &( ((mbedtls_ecp_keypair *) ctx)->Q );
}

//----------------------------------------------------------------------------
//----------------- Constants ------------------------------------------------
//----------------------------------------------------------------------------
pkinfo_t kybkey_pkinfo = {
    MBEDTLS_PK_KYBER,
    //&kyb_oid,                 
    //"KYBER",
    kybkey_get_keyparams_wrap,
    NULL,                         // verify is not supported 
    NULL,                         // sign is not supported 
    kybkey_decap_wrap,                          
    kybkey_encap_wrap,                       
    NULL,                         // DH not supported   
    kybkey_keygen_wrap,
    kybkey_check_pair_wrap,
    kybkey_alloc_wrap,            // allocate memory for the context 
    kybkey_free_wrap,             // free key context 
    kybkey_import_wrap,           // import DER formatted key 
    kybkey_export_wrap,           // export key in DER format or in text format 
    kybkey_debug_wrap
};

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
 *  Register the algorithm as a constructor 
 * ---------------------------------------------------------------------------*/
int pkey_kybkey_enable_constructors;  /* not used for anything except for the linker to link the constructor */
void __attribute__ ((constructor)) pkey_kybkey_constructor(void)
{
    pkey_register_pk_algorithm(&kybkey_pkinfo); 
}

#else /* MBEDTLS_KYBER_C */
pkinfo_t *pkey_kyber_get_pkinfo( pktype_e pktype) 
{
    return NULL;
}

#endif /* MBEDTLS_KYBER_C */
#endif /* MBEDTLS_PK_C */
