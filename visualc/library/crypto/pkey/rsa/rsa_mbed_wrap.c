#include "common.h"

#if defined(MBEDTLS_PK_C)
#if defined(MBEDTLS_RSA_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pkpq.h"
#include "crypto_util.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/oid.h"

#define LOGS_PREFIX "    PK_RSA: "
#include "crypto_common.h"

//----------------------------------------------------------------------------
//----------------- Switches -------------------------------------------------
//----------------------------------------------------------------------------
// #define OPENSSL_FORMATTED
  
//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------

#define DEFAULT_RSA_PUBEXP 65537

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
static const uint8_t  oid_data[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static pkbuf_t        rsa_oid = { oid_data, oid_data, sizeof(oid_data), 0}; 

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Local Functions ------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/*
 * Wrapper around mbedtls_asn1_get_mpi() that rejects zero.
 *
 * The value zero is:
 * - never a valid value for an RSA parameter
 * - interpreted as "omitted, please reconstruct" by mbedtls_rsa_complete().
 *
 * Since values can't be omitted in PKCS#1, passing a zero value to
 * rsa_complete() would be incorrect, so reject zero values early.
 */
static int asn1_get_nonzero_mpi( uint8_t **p, const uint8_t *end, mbedtls_mpi *X )
{
    int ret;

    ret = mbedtls_asn1_get_mpi( p, end, X );
    if( ret != 0 )
        return( ret );

    if( mbedtls_mpi_cmp_int( X, 0 ) == 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );

    return SUCCESS;
}


/******************************************************************************
 * Description:  RSAPublicKey ::= SEQUENCE {              
 *                   modulus           INTEGER,  -- n     
 *                   publicExponent    INTEGER   -- e     
 *               }
 * 
 * Arguments:   p        - pointer to DER key pointer
 *              end      - end of the DER key data 
 *              rsakey      - rsakey key context 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int get_rsapubkey( rsakey_t *rsakey, uint8_t **p, const uint8_t *end, size_t *der_olen) 
{
    uint8_t *start = *p;   // save the start pointer
    size_t   len;
    int      rc = LIB_ERROR;

    /*---------------------Code ----------------------------------------------*/
    if( ( rc = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto fail_invalid_format;

    if( *p + len > end ) {
        rc = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto fail_invalid_format; 
    }
    SET_VAL_SAFE(der_olen, (size_t)(*p - start) + len);

    /* Import N */
    if( ( rc = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ) ) != 0 )
        goto fail_invalid_format; 

    if( ( rc = mbedtls_rsa_import_raw( rsakey, *p, len, NULL, 0, NULL, 0, NULL, 0, NULL, 0 ) ) != 0 )
        goto fail_invalid_pubkey;

    *p += len;

    /* Import E */
    if( ( rc = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ) ) != 0 )
        goto fail_invalid_format; 

    if( ( rc = mbedtls_rsa_import_raw( rsakey, NULL, 0, NULL, 0, NULL, 0, NULL, 0, *p, len ) ) != 0 )
        goto fail_invalid_pubkey;

    *p += len;

    if( mbedtls_rsa_complete( rsakey ) != 0 ||
        mbedtls_rsa_check_pubkey( rsakey ) != 0 )
    {
        goto fail_invalid_pubkey;
    }

    if( *p != end ) {
        rc = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto fail_invalid_format;
    }
    return SUCCESS;


    // --- Error handling --- 
fail_invalid_pubkey:
    rc = MBEDTLS_ERR_PK_INVALID_PUBKEY; goto fail;
fail_invalid_format: 
    rc = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_INVALID_PUBKEY, rc );
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    SET_VAL_SAFE( der_olen, 0); 
    return rc;
}


/******************************************************************************
 *
 * Description: Parse a PKCS#1 encoded private RSA ke
 *
 * Arguments:   rsakey   - rsakey key context 
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *
 *****************************************************************************/
static int parse_key_pkcs1_der( rsakey_t *rsakey, const uint8_t *key, size_t klen, size_t *der_olen)
{
    uint8_t   *p, *end;
    size_t     len;
    int        rc, version;


    /*---------------------Code ----------------------------------------------*/
    mbedtls_mpi T;
    mbedtls_mpi_init( &T );

    p   = (uint8_t *) key;
    end = p + klen;

    /*
     * This function parses the RSAPrivateKey (PKCS#1)
     *
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto fail_invalid_format;

    end = p + len;
    SET_VAL_SAFE( der_olen, (size_t)(p - key) + len);  // Set the size of the DER key 

    if( ( rc = mbedtls_asn1_get_int( &p, end, &version ) ) != 0 )
        goto fail_invalid_format;

    if( version != 0 )
        goto fail_invalid_version;

    /* Import N */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_rsa_import( rsakey, &T, NULL, NULL, NULL, NULL ) ) != 0 )
        goto fail_invalid_format;

    /* Import E */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_rsa_import( rsakey, NULL, NULL, NULL, NULL, &T ) ) != 0 )
        goto fail_invalid_format;

    /* Import D */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_rsa_import( rsakey, NULL, NULL, NULL, &T, NULL ) ) != 0 )
        goto fail_invalid_format;

    /* Import P */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_rsa_import( rsakey, NULL, &T, NULL, NULL, NULL ) ) != 0 )
        goto fail_invalid_format;

    /* Import Q */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_rsa_import( rsakey, NULL, NULL, &T, NULL, NULL ) ) != 0 )
        goto fail_invalid_format;

#if !defined(MBEDTLS_RSA_NO_CRT) && !defined(MBEDTLS_RSA_ALT)
    /*
    * The RSA CRT parameters DP, DQ and QP are nominally redundant, in
    * that they can be easily recomputed from D, P and Q. However by
    * parsing them from the PKCS1 structure it is possible to avoid
    * recalculating them which both reduces the overhead of loading
    * RSA private keys into memory and also avoids side channels which
    * can arise when computing those values, since all of D, P, and Q
    * are secret. See https://eprint.iacr.org/2020/055 for a
    * description of one such attack.
    */

    /* Import DP */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_mpi_copy( &rsakey->DP, &T ) ) != 0 )
        goto fail_invalid_format;

    /* Import DQ */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_mpi_copy( &rsakey->DQ, &T ) ) != 0 )
        goto fail_invalid_format;

    /* Import QP */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = mbedtls_mpi_copy( &rsakey->QP, &T ) ) != 0 )
        goto fail_invalid_format;

#else
    /* Verify existance of the CRT params */
    if( ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 ||
        ( rc = asn1_get_nonzero_mpi( &p, end, &T ) ) != 0 )
        goto fail_invalid_format;
#endif

    /* rsa_complete() doesn't complete anything with the default
     * implementation but is still called:
     * - for the benefit of alternative implementation that may want to
     *   pre-compute stuff beyond what's provided (eg Montgomery factors)
     * - as is also sanity-checks the key
     *
     * Furthermore, we also check the public part for consistency with
     * mbedtls_pk_parse_pubkey(), as it includes size minima for example.
     */
    if( ( rc = mbedtls_rsa_complete( rsakey ) ) != 0 ||
        ( rc = mbedtls_rsa_check_pubkey( rsakey ) ) != 0 )
    {
        goto fail;
    }

    if( p != end )
    {
        rc = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        goto fail;
    }
    return SUCCESS;


    // --- Error handling --- 
fail_invalid_version:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_VERSION; goto fail;
fail_invalid_format: 
    if( ( rc & 0xff80 ) == 0 )
        rc = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc );
    else
        rc = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
fail:
    mbedtls_mpi_free( &T );
    mbedtls_rsa_free( rsakey );
    SET_VAL_SAFE( der_olen, 0); 
    return rc;
}


/******************************************************************************
 * Description: Export a PKCS#8 encoded DER formatted private key 
 *
 * Arguments:   rsakey      - rsakey key context
 *              odata       - contianer for the output data (OUT) 
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int rsakey_export_der_pkcs8( rsakey_t *rsakey,  pkbuf_t *odata)
{
    mbedtls_mpi  T;      // Temporary holding the exported parameters 
    uint8_t     *c;      // active pointer in the buffer 
    uint8_t     *start;  // Start of the buffer 
    const char  *oid;
    size_t       osize, len = 0, oid_len, par_len=0;
    int          version, rc;

    /*---------------------Code ----------------------------------------------*/
    pkbuf_extract(odata, &start, &osize, &len); 
    c = start + osize; 

    // Export the parameters one after another to avoid simultaneous copies.
    mbedtls_mpi_init(&T);

    /* Export QP */
    if ((rc = mbedtls_rsa_export_crt(rsakey, NULL, NULL, &T)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    /* Export DQ */
    if ((rc = mbedtls_rsa_export_crt(rsakey, NULL, &T, NULL)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    /* Export DP */
    if ((rc = mbedtls_rsa_export_crt(rsakey, &T, NULL, NULL)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    /* Export Q */
    if ((rc = mbedtls_rsa_export(rsakey, NULL, NULL, &T, NULL, NULL)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    /* Export P */
    if ((rc = mbedtls_rsa_export(rsakey, NULL, &T, NULL, NULL, NULL)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    /* Export D */
    if ((rc = mbedtls_rsa_export(rsakey, NULL, NULL, NULL, &T, NULL)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    /* Export E */
    if ((rc = mbedtls_rsa_export(rsakey, NULL, NULL, NULL, NULL, &T)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    /* Export N */
    if ((rc = mbedtls_rsa_export(rsakey, &T, NULL, NULL, NULL, NULL)) != 0 ||
        (rc = mbedtls_asn1_write_mpi(&c, start, &T)) < 0)
        goto fail;
    len += rc;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, start, 0));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));


    /* PKCS8 
    *    PrivateKeyInfo ::= SEQUENCE {
    *      version                   Version,
    *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    *      privateKey                PrivateKey,
    *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
    *
    *    Version ::= INTEGER
    *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    *    PrivateKey ::= OCTET STRING
    */

    // Write Private octet string len and tag 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_OCTET_STRING));

    // Write PK algorithm OID: Use the hardcoded oid data 
    oid     = (const char*)rsa_oid.buf;
    oid_len = rsa_oid.size;

    // Write PK algorithm OID  
    ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, start, oid, oid_len, par_len));

    // Write version 
    version = 0; 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, start, version));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    odata->iolen = len; 
    // printf("%s(): Wrote %d DER bytes\n", __func__, (int)len); 
    rc = len; 
    goto cleanup;

    // --- Error handling ---
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    mbedtls_platform_zeroize( (void*) odata->buf, odata->size);
    odata->iolen = 0; 
cleanup:
    mbedtls_mpi_free(&T);
    return (rc);
}


/******************************************************************************
 * Description: Export a PKCS#8 encoded DER formatted public key 
 *              RSAPublicKey ::= SEQUENCE {
 *                  modulus           INTEGER,  -- n
 *                  publicExponent    INTEGER   -- e
 *
 * Arguments:   rsakey      - rsakey key context
 *              odata       - contianer for the output data (OUT) 
 *
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int rsakey_export_pubkey_der( rsakey_t *rsakey,  pkbuf_t *odata)
{
    mbedtls_mpi  T;      // Temporary holding the exported parameters 
    uint8_t     *c;      // active pointer in the buffer 
    uint8_t     *start;  // Start of the buffer 
    const char  *oid;
    size_t       osize, len = 0, oid_len, par_len = 0;
    int          rc;

    /*---------------------Code ----------------------------------------------*/
    pkbuf_extract(odata, &start, &osize, &len); 
    c = start + osize; 
    mbedtls_mpi_init( &T );

    /* Export E */
    if ( ( rc = mbedtls_rsa_export( rsakey, NULL, NULL, NULL, NULL, &T ) ) != 0 ||
         ( rc = mbedtls_asn1_write_mpi( &c, start, &T ) ) < 0 )
        goto fail;
    len += rc;

    /* Export N */
    if ( ( rc = mbedtls_rsa_export( rsakey, &T, NULL, NULL, NULL, NULL ) ) != 0 ||
         ( rc = mbedtls_asn1_write_mpi( &c, start, &T ) ) < 0 )
        goto fail;
    len += rc;

    ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, start, len ) );
    ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_BIT_STRING));

    // Write PK algorithm OID: Use the hardcoded oid data 
    oid     = (const char*)rsa_oid.buf;
    oid_len = rsa_oid.size;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, start, oid, oid_len, par_len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    odata->iolen = len; 
    // printf("%s(): Wrote %d DER bytes\n", __func__, (int)len); 
    rc = len; 
    goto cleanup;

    // --- Error handling ---
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    mbedtls_platform_zeroize( (void*)odata->buf, odata->size);
    odata->iolen = 0; 
cleanup:
    mbedtls_mpi_free(&T);
    return (rc);
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
static int rsakey_export_key_text(rsakey_t *rsakey, pktarget_e target, pkexport_e level, pkbuf_t *result)
{
    pkbuf_t  odata; 
    size_t   bitlen = 0;

    /*---------------------Code ----------------------------------------------*/
    pkbuf_init( &odata, (uint8_t *)result->buf, result->size, result->iolen); // Make a modifiable copy 
    *(uint8_t*)(odata.buf + odata.size - 1) = 0;              // Null terminate, just in case

    bitlen = rsakey->len * 8;
    memset( (uint8_t *)result->buf, 0, result->size);
    if (target == PK_TARGET_PRV)
        odata.iolen = snprintf( (char *)odata.buf, odata.size, "RSA Private-Key: (%d bit, 2 primes)\n", (int)bitlen );
    else
        odata.iolen = snprintf( (char *)odata.buf, odata.size, "RSA Public-Key: (%d bit)\n", (int)bitlen );

    util_write_mpi_formatted( &rsakey->N, 0, &odata, "modulus" );
    util_write_mpi_formatted( &rsakey->E, 0, &odata, "publicExponent" );
    if (target == PK_TARGET_PRV)
    {
        util_write_mpi_formatted( &rsakey->D, rsakey->len, &odata, "privateExponent" );
        if (level >= PK_EXPORT_EXTENDED)
        {
            util_write_mpi_formatted( &rsakey->P, 0, &odata, "prime1" );
            util_write_mpi_formatted( &rsakey->Q, 0, &odata, "prime2" );
            if (level >= PK_EXPORT_FULL)
            {
                util_write_mpi_formatted( &rsakey->DP, 0, &odata, "exponent1" );
                util_write_mpi_formatted( &rsakey->DQ, 0, &odata, "exponent2" );
                util_write_mpi_formatted( &rsakey->QP, 0, &odata, "coefficient" );
            }
        }
    }
    // Update the length of the data written
    result->iolen = result->size - odata.size;
    result->iolen += snprintf( (char *)odata.buf, odata.size, "\n\n");
    
    return result->iolen;
}


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- RSA wrapper Functions ------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
  * Description: get the key paramater info 
  *
  * Arguments:   pkctx    - RSA key context 
  *
  * result:      pointer to the key paramaters structure 
  *****************************************************************************/
static pk_keyparams_t *rsa_get_keyparams( void *pkctx)  
{   
    rsakey_t              *rsakey = (rsakey_t*)pkctx;                                       
    size_t                 len;
    struct pk_keyparams_s *kparms = (struct pk_keyparams_s *)rsakey->key_params;

    if (kparms->initialized == 0 )
    {
        if( (len = mbedtls_rsa_get_len( rsakey )) != 0) 
        {
            kparms->sig_len = len; 
            kparms->ct_len  = len; 
            kparms->ss_len  = 32; 
            kparms->name    = "RSA"; 
            memcpy( &kparms->oid, &rsa_oid, sizeof(pkbuf_t)); 

            kparms->initialized = 1; 
        }
    }
    return kparms;
}


/* ---------------------------------------------------------------------------
 * RSA get bitlen wrapper 
 * ---------------------------------------------------------------------------*/
//static int rsa_get_bitlen_wrap( void *ctx, size_t *bitlen )
//{
 //   const rsakey_t * rsakey = (const rsakey_t *) ctx;
 //   *bitlen =  8 * mbedtls_rsa_get_len( rsakey );
 //   return SUCCESS;
//}


/* ---------------------------------------------------------------------------
 * RSA verify wrapper 
 * ---------------------------------------------------------------------------*/
static int rsa_vrfy_wrap( void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig, void* rs_ctx)
{
    rsakey_t *rsakey = (rsakey_t *)pkctx;
    size_t               rsa_len = mbedtls_rsa_get_len( rsakey );
    int                  rc; 
    (void) rs_ctx;


    /*---------------------Code ----------------------------------------------*/
  #if SIZE_MAX > UINT_MAX
    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash->size)
        goto fail_bad_data;
  #endif /* SIZE_MAX > UINT_MAX */

    if (sig->size < rsa_len)
        goto fail_bad_data;

    if( (rc = mbedtls_rsa_pkcs1_verify(rsakey, md_alg, (uint_t)hash->size, hash->buf, sig->buf)) != SUCCESS)
        goto fail;

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use mbed_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    //if (sig->size > rsa_len)
    //     goto fail_sig_len; 
    sig->iolen = rsa_len;  // Return the number of bytes in hte signature 
    return SUCCESS;


    // --- Error handling --- 
fail_bad_data: 
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA; goto fail; 
//fail_sig_len: 
//    rc = MBEDTLS_ERR_PK_SIG_LEN_MISMATCH; 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    sig->iolen = 0;
    return rc; 
}


/* ---------------------------------------------------------------------------
 * RSA sign wrapper 
 * ---------------------------------------------------------------------------*/
static int rsa_sign_wrap( void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig_out, void *rs_ctx)
{
    rsakey_t        *rsakey = (rsakey_t *)pkctx;
    rnginfo_t       *rng; 
    int              rc = -1; 
    (void) rs_ctx;

    /*---------------------Code ----------------------------------------------*/
 #if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash->size )
        goto fail_bad_data;
  #endif /* SIZE_MAX > UINT_MAX */

    sig_out->iolen = mbedtls_rsa_get_len(rsakey);
    if (sig_out->size  < sig_out->iolen)
        goto fail_bufsz; 

    if(( rc= pkey_get_rng_info((pktop_t *)rsakey->pktop, &rng )) != SUCCESS)
        goto fail;  

    rc = mbedtls_rsa_pkcs1_sign(rsakey, rng->cb, rng->ctx, md_alg, (uint_t)hash->size, hash->buf,(uint8_t*)sig_out->buf);
    if (rc != SUCCESS)
        goto fail; 
    return SUCCESS; 


    // --- Error handling --- 
fail_bad_data: 
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA; goto fail;
fail_bufsz: 
    rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; goto fail;
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    sig_out->iolen = 0; 
    return rc;                                                                                        
}

/* ---------------------------------------------------------------------------
 * RSA decapsulate wrapper 
 * ---------------------------------------------------------------------------*/
static int rsa_decap_wrap( void *pkctx, capmode_e mode, pkbuf_t *m, pkbuf_t *result)
{
    rsakey_t *rsakey = (rsakey_t *)pkctx;
    rnginfo_t           *rng; 
    int                  rc; 
    

    /*---------------------Code ----------------------------------------------*/
    if( m->size != mbedtls_rsa_get_len( rsakey ) )
        goto fail_bad_data;

    if(( rc= pkey_get_rng_info((pktop_t *)rsakey->pktop, &rng )) != SUCCESS)
        goto fail;  

    if ( mode == MBED_CAPMODE_PKCS1_5) 
        rc = mbedtls_rsa_pkcs1_decrypt(rsakey, rng->cb, rng->ctx, &result->iolen, m->buf, (uint8_t*)result->buf, result->size);
    else if (mode == MBED_CAPMODE_OEAP) 
        rc = mbedtls_rsa_rsaes_oaep_decrypt(rsakey, rng->cb, rng->ctx, NULL, 0, &result->iolen, m->buf, (uint8_t*)result->buf, result->size);
    else 
        goto fail_capmode; 


    if (rc != SUCCESS)
        goto fail; 
    return SUCCESS;

    // --- Error handling --- 
fail_capmode:
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA; goto fail_log; 
fail_bad_data: 
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA; 
fail_log: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
fail: 
    return rc;                                                                                        
}


/* ---------------------------------------------------------------------------
 * RSA encapsulate wrapper 
 *      mode    - encapsulation mode (e.g. MBED_CAPMODE_PKCS1_5 ) 
 *      m       - message in
 *      result  - encapsulated result 
 * ---------------------------------------------------------------------------*/
static int rsa_encap_wrap(void *pkctx, capmode_e mode, pkbuf_t *m, pkbuf_t *result)
{
    rsakey_t   *rsakey = (rsakey_t *)pkctx;
    rnginfo_t  *rng;
    int         rc;


    /*---------------------Code ----------------------------------------------*/
    if (result->size < m->size)
        goto fail_output_size;

    if(( rc= pkey_get_rng_info((pktop_t *)rsakey->pktop, &rng )) != SUCCESS)
        goto fail;  

    LOGD("%s() encapsulation mode (capmode) = %d\n", __func__, mode ); 
    if (mode == MBED_CAPMODE_PKCS1_5) {
        rc = mbedtls_rsa_pkcs1_encrypt(rsakey, rng->cb, rng->ctx, m->size, m->buf, (uint8_t*)result->buf);
    } else if (mode == MBED_CAPMODE_OEAP) {
        rc = mbedtls_rsa_rsaes_oaep_encrypt(rsakey, rng->cb, rng->ctx, NULL, 0, m->size, m->buf, (uint8_t*)result->buf);
    } else {
        goto fail_capmode; 
    }
    if (rc != SUCCESS)
        goto fail;

    m->iolen      = m->size;  // complete message is consumed
    result->iolen = mbedtls_rsa_get_len(rsakey);
    return SUCCESS;

    // --- Error handling ---
fail_capmode:
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA; goto fail_log; 
fail_output_size:
    rc = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
fail_log: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
fail:
    result->iolen = 0;
    return rc;
}


/* ---------------------------------------------------------------------------
 * RSA keygen wrapper 
 * ---------------------------------------------------------------------------*/
static int rsa_keygen_wrap(void *pkctx, char* keygen_params)
{
    rsakey_t   *rsakey = (rsakey_t *)pkctx;
    rnginfo_t  *rng; 
    char       *rest, *token;
    size_t      rsa_size, rsa_exp; 
    int         rc; 


    /*---------------------Code ----------------------------------------------*/
    // parse the keygen_params
    rest = keygen_params; 
    rsa_size = 3072; 
    rsa_exp  = DEFAULT_RSA_PUBEXP; 
    while ((token = strtok_r(rest, ":", &rest)))
    {
        if (strncmp(token, "size=", 5) == 0) 
            rsa_size = atoi(token+5);
        else if (strncmp(token, "exp=", 4) == 0) 
            rsa_exp = atoi(token+4);
        else
            goto fail_bad_input;
    }
    LOGD("rsa_size=%d, rsa_exp=%d\n", (int)rsa_size, (int)rsa_exp);
    if (rsa_size != 1024 &&  rsa_size != 2048 && rsa_size != 3072 && rsa_size != 4096)
        goto fail_bad_input;
    if ((rsa_exp != 3) && (rsa_exp != DEFAULT_RSA_PUBEXP))
        goto fail_bad_input;

    if(( rc= pkey_get_rng_info((pktop_t *)rsakey->pktop, &rng )) != SUCCESS)
        goto fail;  

    if ((rc = mbedtls_rsa_gen_key(rsakey, rng->cb, rng->ctx, rsa_size, rsa_exp)) != 0)
        goto fail; 
    return SUCCESS; 

fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
fail: 
    return rc;
}


/* ---------------------------------------------------------------------------
 * RSA check_pair wrapper 
 * ---------------------------------------------------------------------------*/
static int rsa_check_pair_wrap( void *pkctx_pub, void *pkctx_prv)
{
    return mbedtls_rsa_check_pub_priv((const rsakey_t *)pkctx_pub, (const rsakey_t *)pkctx_prv);
}


/* ---------------------------------------------------------------------------
 * RSA alloc rsakey key context wrapper  
 * ---------------------------------------------------------------------------*/
static void *rsa_alloc_wrap( pkfull_t *pkfull )
{
    rsakey_t *rsakey = (rsakey_t*)mbed_calloc( 1, sizeof( rsakey_t) );

    if( rsakey != NULL ) {
        mbedtls_rsa_init( (rsakey_t *) rsakey );
        rsakey->key_params = mbed_calloc( 1, sizeof(pk_keyparams_t)); 
        rsakey->pktop  = (void *)pkfull->pktop;  // Reference back to the top level
    }
    return( rsakey );
}


/* ---------------------------------------------------------------------------
 * RSA free rsakey context wrapper  
 * ---------------------------------------------------------------------------*/
static void *rsa_free_wrap( void *pkctx )
{
    rsakey_t *rsakey = (rsakey_t*)pkctx; 

    mbedtls_rsa_free(rsakey);
    rsakey->key_params = mbed_free( rsakey->key_params);
    mbed_free( pkctx );
    return NULL;
}

/* ---------------------------------------------------------------------------
 * RSA wrapper function to import a DER key 
 * ---------------------------------------------------------------------------*/
static int rsa_import_wrap( void *pkctx, pktarget_e target, pkbuf_t *kdata, void *alg_info, size_t *der_olen) 
{
    rsakey_t *rsakey = (rsakey_t*)pkctx; 
    int       rc; 
    (void) alg_info; 

    /*---------------------Code ----------------------------------------------*/
    if (target == PK_TARGET_PRV)
        rc = parse_key_pkcs1_der(rsakey, kdata->buf, kdata->size, der_olen); 
    else if (target == PK_TARGET_PUB)
    {
        uint8_t *p = (uint8_t *)kdata->buf;
        rc = get_rsapubkey(rsakey, &p, p + kdata->size, der_olen);
    }
    else 
        rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 

    if (rc != SUCCESS)
        goto fail; 
    return SUCCESS; 

fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * RSA wrapper function to export a key 
 * level of export: 0 is DER, 1=BASIC, 2=EXTENDED, 3=FULL  
 * ---------------------------------------------------------------------------*/
static int rsa_export_wrap( void *pkctx, pktarget_e target, pkexport_e level, pkbuf_t *result) 
{
    rsakey_t *rsakey = (rsakey_t*)pkctx; 
    int       rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( level == PK_EXPORT_DER)
    {
        if (target == PK_TARGET_PRV)
            rc = rsakey_export_der_pkcs8(rsakey, result);
        else if (target == PK_TARGET_PUB || target == PK_TARGET_PUBSSL || target == PK_TARGET_PUBSSL_RESP)
            rc = rsakey_export_pubkey_der(rsakey, result);
        else 
            rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    }
    else
    {
        rc = rsakey_export_key_text(rsakey, target, level, result); 
    }

    if (rc < 0)
        goto fail; 
    return SUCCESS;

fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}



/* ---------------------------------------------------------------------------
 * RSA free rsakey context wrapper  
 * ---------------------------------------------------------------------------*/
static void rsa_debug( void *pkctx, mbedtls_pk_debug_item *items )
{
    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsakey.N";
    items->value = &( ((rsakey_t *) pkctx)->N );

    items++;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsakey.E";
    items->value = &( ((rsakey_t *) pkctx)->E );
}

//----------------------------------------------------------------------------
//----------------- Constants ------------------------------------------------
//----------------------------------------------------------------------------
pkinfo_t rsa_pkinfo = {
    MBEDTLS_PK_RSA,
    //&rsa_oid, 
    //"RSA",
    rsa_get_keyparams,
    rsa_vrfy_wrap,
    rsa_sign_wrap,
    rsa_decap_wrap,
    rsa_encap_wrap,
    NULL,                        // shared secret not supported     
    rsa_keygen_wrap,
    rsa_check_pair_wrap,
    rsa_alloc_wrap,
    rsa_free_wrap,
    rsa_import_wrap,
    rsa_export_wrap,
    rsa_debug
};

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
 *  Register the algorithm as a constructor 
 * ---------------------------------------------------------------------------*/
int pkey_rsakey_enable_constructors;  /* not used for anything except for the linker to link the constructor */
void __attribute__ ((constructor)) pkey_rsakey_constructor(void)
{
    pkey_register_pk_algorithm(&rsa_pkinfo); 
}
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PK_C */
