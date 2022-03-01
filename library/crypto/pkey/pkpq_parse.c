/*
 *  Public Key layer for parsing key files and structures
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

#if defined(MBEDTLS_PK_PARSE_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "pkpq_parse.h"
#include "pkpq.h"
#include "crypto_util.h"

#define LOGS_PREFIX "  PK_PARSE: "
#include "crypto_common.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif
#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif
#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#endif

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define PKTYPE_DER_ENCRYPTED   (MBEDTLS_PK_LAST+1)     // Mixes with pkype_e, needs to be cleaned up 
#define PKTYPE_DER_PKCS8       (MBEDTLS_PK_LAST+2)
#define PKTYPE_SUBPUBKEY       (MBEDTLS_PK_LAST+3) 


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Local Functions  -----------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
 * Description: Get a PK algorithm identifier 
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int pk_get_pk_alg( uint8_t **p, const uint8_t *end, pktype_e *pktype_out, mbedtls_asn1_buf *params )
{
    mbedtls_asn1_buf  alg_oid;
    pktype_e          pktype; 
    int               ret = LIB_ERROR;

    /*---------------------Code ----------------------------------------------*/
    memset( params, 0, sizeof(mbedtls_asn1_buf) );

    if( ( ret = mbedtls_asn1_get_alg( p, end, &alg_oid, params ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_INVALID_ALG, ret ) );

    // util_dump(alg_oid.p, alg_oid.len, "OID found"); 

    if( mbedtls_oid_get_pk_alg( &alg_oid, (hybpk_t*)&pktype ) != 0 )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if (pktype != MBEDTLS_PK_ECKEY && pktype != MBEDTLS_PK_ECKEY_DH && pktype != MBEDTLS_PK_ECDSA)
    {
        // There should be only paramaters in case of EC)
        if ( (params->tag != MBEDTLS_ASN1_NULL && params->tag != 0) || (params->len != 0))
        {
            LOGD("%s(): Unexpected paramaters for type %d\n", __func__, (int)pktype); 
            return( MBEDTLS_ERR_PK_INVALID_ALG );
        }
    }
    *pktype_out = pktype; 

    return SUCCESS;
}


/******************************************************************************
 * Description: Clean a full key context, This is different than freeing !!!!
 *
 * Arguments:   pkfull  - pointer to the context
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int pk_pkfull_clean( pkfull_t *pkfull)
{
    pktop_t          *saved_pktop; 
    struct pkfull_s  *pkfull_mod = (struct pkfull_s *)pkfull;

    /*---------------------Code ----------------------------------------------*/
    saved_pktop = pkfull->pktop; 
    if ( pkfull->pkctx != NULL && pkfull->pkinfo != NULL ) 
        pkfull->pkinfo->ctx_free_func(pkfull->pkctx);

    // Clean the key data.  
    mbedtls_platform_zeroize( (void*)pkfull, sizeof( pkfull_t) );
    pkfull_mod->pktop = saved_pktop; 

    return SUCCESS;
}

/******************************************************************************
 * Description: Import an unencrypted DER formatted key 
 *
 * Arguments:   pkfull   - full key context 
 *              key      - 'PEM' key data
 *              klen     - size of the data 
 *              pktype   - pktype of the data or MBEDTLS_PK_NONE if unknown
 *              der_olen - container for the sizeof th parsed DER data 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int pk_import_prv_key(pkfull_t *pkfull_in, pkbuf_t *idata, pktype_e  pktype, asn1buf_t* params, size_t *der_olen)
{
    struct pkfull_s  *pkfull = (struct pkfull_s *)pkfull_in;  // make pkfull modifiable 
    pkinfo_t         *pkinfo; 
    int               rc; 

    /*---------------------Code ----------------------------------------------*/
    if ((rc = pkey_pkfull_setup(pkfull, pkfull->pktop, pktype)) != SUCCESS)
        goto fail;
    pkfull->is_pub = FALSE;  // make pkfull modifiable

    pkinfo = pkfull->pkinfo;
    // Call the generic key import function from the pkey algorithm 
    if( (rc = pkinfo->import_func(pkfull->pkctx, pkfull->is_pub, idata, params, der_olen)) != SUCCESS)
        goto fail; 
    return SUCCESS;

fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    pk_pkfull_clean(pkfull); // Clean the key context on fail
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/******************************************************************************
 * Description: Import an unencrypted DER formatted key 
 *
 * Arguments:   pkfull   - full key context 
 *              key      - 'PEM' key data
 *              klen     - size of the data 
 *              pktype   - pktype of the data or MBEDTLS_PK_NONE if unknown
 *              alg_info - opaque pointer to algoritm spsicific info like
 *                         curve parameters or key prototyep 
 *              der_olen - container for the sizeof th parsed DER data 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int pk_import_pub_key(pkfull_t *pkfull_in, pkbuf_t *idata, pktarget_e target, 
                             pktype_e  pktype, void* alg_info, size_t *der_olen)
{
    struct pkfull_s  *pkfull = (struct pkfull_s *)pkfull_in;  // make pkfull modifiable 
    pkinfo_t         *pkinfo; 
    int               rc; 

    /*---------------------Code ----------------------------------------------*/
    if ((rc = pkey_pkfull_setup(pkfull, pkfull->pktop, pktype)) != SUCCESS)
        goto fail;
    pkfull->is_pub = TRUE;   

    pkinfo = pkfull->pkinfo;

    // Call the generic key import function from the pkey algorithm 
    if( (rc = pkinfo->import_func(pkfull->pkctx, target, idata, alg_info, der_olen)) != SUCCESS)
        goto fail; 
    // Call the generic key import function from the pkey algorithm 
    return SUCCESS;

fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    pk_pkfull_clean(pkfull); // Clean the key context on fail
    return rc; 
}



/* ---------------------------------------------------------------------------
 * Parse an unencrypted PKCS#8 encoded private key
 *
 * Notes:
 *
 * - This function does not own the key buffer. It is the
 *   responsibility of the caller to take care of zeroizing
 *   and freeing it after use.
 *
 * - The function is responsible for freeing the provided
 *   PK context on failure.
 * ---------------------------------------------------------------------------*/
/******************************************************************************
 *
 * Description: Parse an unencrypted PKCS#8 encoded private key
 *              Notes:                                                        
 *              - This function does not own the key buffer. It is the        
 *                responsibility of the caller to take care of zeroizing      
 *                and freeing it after use.                                   
 *              - The function is responsible for freeing the provided        
 *
 * Arguments:   pkfull   - PK key 'full' context  
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *
 *****************************************************************************/
static int parse_key_pkcs8_unencrypted_der( pkfull_t *pkfull, pkbuf_t *kdata, size_t *der_olen)
{
    pktype_e          pktype = MBEDTLS_PK_NONE;
    mbedtls_asn1_buf  params;
    uint8_t          *p, *end;
    size_t            len; 
    int               rc, version;


    /*---------------------Code ----------------------------------------------*/
    p   = (uint8_t *)kdata->buf;
    end = p + kdata->size;

    /*
     * This function parses the PrivateKeyInfo object (PKCS#8 v1.2 = RFC 5208)
     *
     *    PrivateKeyInfo ::= SEQUENCE {
     *      version                   Version,
     *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *      privateKey                PrivateKey,
     *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
     *
     *    Version ::= INTEGER
     *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *    PrivateKey ::= OCTET STRING
     *
     *  The PrivateKey OCTET STRING is a SEC1 ECPrivateKey
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto fail_invalid_format;

    
    end = p + len;
   //     printf("p=%p, key=%p, len=%d\n", (void*)p, (void*)key, (int)len); 
    SET_VAL_SAFE( der_olen, (size_t)(p - kdata->buf) + len );  // Set the size of the DER key

    if( ( rc = mbedtls_asn1_get_int( &p, end, &version ) ) != 0 )
        goto fail_invalid_format;

    if( version != 0 )
        goto fail_invalid_version;

    if( ( rc = pk_get_pk_alg( &p, end, &pktype, &params ) ) != 0 )
        goto fail; 
    
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        goto fail_invalid_format;

    if( len < 1 ) 
    {
        rc = MBEDTLS_ERR_ASN1_OUT_OF_DATA; 
        goto fail_invalid_format;
    }

    if( pktype > MBEDTLS_PK_NONE &&  pktype < MBEDTLS_PK_LAST) 
    {
        pkbuf_t idata; 

        pkbuf_init(&idata, p, len, 0 );  // Compress to pkbuf_t 
        if( (rc = pk_import_prv_key( pkfull, &idata, pktype, &params, NULL)) != SUCCESS)
            goto fail; 
        return SUCCESS; 
    }
    else
    {
        rc = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG; 
        goto fail;
    }
    return SUCCESS;


     // --- Error handling --- 
fail_invalid_version:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_VERSION; goto fail; 
fail_invalid_format: 
    rc = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc); 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    pk_pkfull_clean( pkfull );
    SET_VAL_SAFE( der_olen, 0);  // Set the size of the DER key 
    return rc;       
}


/******************************************************************************
 *
 * Description: Parse an encrypted PKCS#8 encoded private key                                  
 *                                                                                              
 *              To save space, the decryption happens in-place on the given key buffer.         
 *              Also, while this function may modify the keybuffer, it doesn't own it,          
 *              and instead it is the responsibility of the caller to zeroize and properly      
 *              free it after use.                                                              
 *
 * Arguments:   pkfull   - PK key 'full' context  
 *              kdata    - DER key data
 *              pwd_data - password data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *
 *****************************************************************************/
#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
static int parse_key_pkcs8_encrypted_der( pkfull_t *pkfull, pkbuf_t *kdata, pkbuf_t *pwd_data, size_t *der_olen) 
{
  #if defined(MBEDTLS_PKCS12_C)
    mbedtls_cipher_type_t  cipher_alg;
    mdtype_e               md_alg;
  #endif
    mbedtls_asn1_buf       pbe_alg_oid, pbe_params;
    pkbuf_t                unenc_kdata; // unencrypted key data 
    const uint8_t         *pwd; 
    uint8_t               *buf;
    uint8_t               *p, *end;
    size_t                 len, pwdlen;
    int                    rc, decrypted = 0;

    /*---------------------Code ----------------------------------------------*/
    p = (uint8_t *)kdata->buf;
    end = p + kdata->size;
    pkbuf_extract_const(pwd_data, &pwd, &pwdlen, NULL);  // expand the pwd data 

    if( pwd_data->size == 0 )
    {
        rc = MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
        goto fail; 
    }

    /*
     * This function parses the EncryptedPrivateKeyInfo object (PKCS#8)
     *
     *  EncryptedPrivateKeyInfo ::= SEQUENCE {
     *    encryptionAlgorithm  EncryptionAlgorithmIdentifier,
     *    encryptedData        EncryptedData
     *  }
     *
     *  EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
     *
     *  EncryptedData ::= OCTET STRING
     *
     *  The EncryptedData OCTET STRING is a PKCS#8 PrivateKeyInfo
     *
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto fail_invalid_format;

    end = p + len;
    SET_VAL_SAFE( der_olen, (size_t)(p - kdata->buf) + len);  // Set the size of the DER key 

    if( ( rc = mbedtls_asn1_get_alg( &p, end, &pbe_alg_oid, &pbe_params ) ) != 0 )
        goto fail_invalid_format;

    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        goto fail_invalid_format;

    buf = p;

    /*
     * Decrypt EncryptedData with appropriate PBE
     */
  #if defined(MBEDTLS_PKCS12_C)
    if (mbedtls_oid_get_pkcs12_pbe_alg(&pbe_alg_oid, &md_alg, &cipher_alg) == 0)
    {
        if ((rc = mbedtls_pkcs12_pbe(&pbe_params, MBEDTLS_PKCS12_PBE_DECRYPT, cipher_alg, md_alg,
                                     pwd, pwdlen, p, len, buf)) != 0)
        {
            if (rc == MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH)
                rc = MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
            goto fail;
        }
        decrypted = 1;
    }
    else
  #endif /* MBEDTLS_PKCS12_C */
  #if defined(MBEDTLS_PKCS5_C)
    if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS5_PBES2, &pbe_alg_oid ) == 0 )
    {
        if( ( rc = mbedtls_pkcs5_pbes2( &pbe_params, MBEDTLS_PKCS5_DECRYPT, pwd, pwdlen, p, len, buf ) ) != 0 )
        {
            if( rc == MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH )
            {
                rc = MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
                goto fail;
            }
            return( rc );
        }
        decrypted = 1;
    }
    else
  #endif /* MBEDTLS_PKCS5_C */
    {
        ((void) pwd);
    }
    if( decrypted == 0 )
    {
        rc = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        goto fail;
    }
    pkbuf_init( &unenc_kdata, buf, len, 0);
    return (parse_key_pkcs8_unencrypted_der(pkfull, &unenc_kdata, NULL));


    // --- Error handling --- 
fail_invalid_format: 
    rc = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc); 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    SET_VAL_SAFE( der_olen, 0);  // Set the size of the DER key 
    return rc;       
}
#endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */



/******************************************************************************
 * Description: Parse a DER formatted private key
 *
 * Arguments:   key     - 'PEM' key data
 *              klen    - size of the data 
 *              pwd     - password data
 *              pwdlen  - password length
 *              pktype  - pktype of the data or MBEDTLS_PK_NONE if unknown 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int parse_der_prv_key(pkfull_t *pkfull, pkbuf_t *kdata, pkbuf_t *pwd_data, pktype_e  pktype, size_t *der_olen)
{
    int      rc = LIB_ERROR;

    /*---------------------Code ----------------------------------------------*/
    if ( ( pktype > MBEDTLS_PK_NONE) && (pktype < MBEDTLS_PK_LAST) )
    {
        // The type of the key is already known so we can import the key. 
        if( (rc = pk_import_prv_key( pkfull, kdata, pktype, NULL, der_olen)) != SUCCESS)
            goto fail;
        goto end; // We are done 
    }
    if (pktype == (int)PKTYPE_DER_PKCS8)
    {
        if ((rc = parse_key_pkcs8_unencrypted_der(pkfull, kdata, der_olen)) != SUCCESS)
            goto fail; 
        goto end; // we are done
    }

  #if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    if (pktype == (int)PKTYPE_DER_ENCRYPTED)
    {
        if ((rc = parse_key_pkcs8_encrypted_der(pkfull, kdata, pwd_data, der_olen)) != SUCCESS)
            goto fail;
        goto end; // we are done
    }
  #endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */

    if (pktype != MBEDTLS_PK_NONE)
        goto fail;     // Unsupported format

    /*
     * At this point we only know it's not a PEM formatted key. Could be any
     * of the known DER encoded private key formats
     *
     * We try the different DER format parsers to see if one passes without
     * error
     */
  #if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    {
        uint8_t *tmp; 
        pkbuf_t  copy_kdata; 

        // Copy the key in case it is not a encrypted key and we need the unencrypted version later  
        //if ((copy_kdata.buf = mbed_calloc(1, kdata->size)) == NULL)
        if ((tmp = mbed_calloc(1, kdata->size)) == NULL)
            return (MBEDTLS_ERR_PK_ALLOC_FAILED);
        memcpy( tmp, kdata->buf, kdata->size);
        pkbuf_init(&copy_kdata, tmp, kdata->size, 0);

        rc = parse_key_pkcs8_encrypted_der(pkfull, &copy_kdata, pwd_data, der_olen);

        mbedtls_platform_zeroize( (uint8_t*)copy_kdata.buf, kdata->size);
        mbed_free( (uint8_t*)copy_kdata.buf);
        if (rc == SUCCESS)
            goto end;   // we are done
        if( rc == MBEDTLS_ERR_PK_PASSWORD_MISMATCH)
           goto fail;
        pk_pkfull_clean(pkfull); // Clean the key context for the next try 
    }
  #endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */

    if ((rc = parse_key_pkcs8_unencrypted_der(pkfull, kdata, der_olen)) == SUCCESS)
        goto end;  // SUCCESS: we are done

    // Try other key formats 
  #if defined(MBEDTLS_RSA_C)
    if ((rc = pk_import_prv_key(pkfull, kdata, MBEDTLS_PK_RSA, NULL, der_olen)) == SUCCESS)
        goto end;
  #endif /* MBEDTLS_RSA_C */
  #if defined(MBEDTLS_ECP_C)
    if ((rc = pk_import_prv_key(pkfull, kdata, MBEDTLS_PK_ECKEY, NULL, der_olen)) == SUCCESS)
        goto end;
  #endif /* MBEDTLS_ECP_C */

fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *der_olen = 0; 
    pk_pkfull_clean(pkfull); // Clean the key context on fail
end:
    return rc;
}


/******************************************************************************
 * Description: Parse a DER formatted public key
 *
 * Arguments:   key     - 'PEM' key data
 *              klen    - size of the data 
 *              pktype  - pktype of the data or MBEDTLS_PK_NONE if unknown 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int parse_der_pub_key( pkfull_t *pkfull, pkbuf_t *kdata, pktype_e  pktype, size_t *der_olen) 
{
    uint8_t  *p;
    int       rc = LIB_ERROR;


    /*---------------------Code ----------------------------------------------*/
    if ( pktype > MBEDTLS_PK_NONE && pktype <  MBEDTLS_PK_LAST) 
    {
        // The type of the key is already known so we can import the key. 
        if( (rc = pk_import_pub_key( pkfull, kdata, PK_TARGET_PUB, pktype, NULL, der_olen)) != SUCCESS)
            goto fail;
        goto end;  // We are done 
    }

    p = (uint8_t *)kdata->buf; 
    
    // Try to see if the DER data is in the form of a subpubkey 
    if ((rc = pkey_parse_subpubkey( pkfull, &p, p + kdata->size, der_olen )) == SUCCESS)
        goto end;

    // Try all other possible key formats 
    // TODO: automatically loop through all registered algorithms 
  #if defined(MBEDTLS_RSA_C)
    if ( (rc = pk_import_pub_key(pkfull, kdata, PK_TARGET_PUB, MBEDTLS_PK_RSA, NULL, der_olen)) == SUCCESS) 
        goto end; 
  #endif /* MBEDTLS_RSA_C */
 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    *der_olen = 0; 
end:
    return rc; 
}


#if defined(MBEDTLS_PEM_PARSE_C)
/******************************************************************************
 *
 * Description: Convert PEM formatted data to DER formatted data for a  key
 *
 * Arguments:   key     - 'PEM' key data
 *              klen    - size of the data 
 *              pwd     - password data ( NULL for public key) 
 *              pwdlen  - password length (0 for public key) 
 *              der_buf - container for DER buffer pointer (OUT) 
 *                        WARNING: der_buf needs to be freed by the caller 
 *              der_len - container for DER buffer length (OUT)
 *              pktype  - container for PK type (OUT) 
 *
 * result:      SUCCESS=0 or error code on failure 
 *
 *****************************************************************************/
static int pem2der_key( pkbuf_t *kdata, pkbuf_t *pwd_data, pktype_e *pktype_out, pkbuf_t *der_data) 
{
    mbedtls_pem_context  pem; 
    const uint8_t       *key, *pwd; 
    char                 header[64], footer[64]; 
    char                *p, *id_str, *alg_str; 
    pktype_e             pktype; 
    size_t               pwdlen, klen, len; 
    int                  rc; 


    /*---------------------Code ----------------------------------------------*/
    mbedtls_pem_init(&pem);
    pkbuf_extract_const( kdata, &key, &klen, NULL);         // expand the pkbuf_t 
    pkbuf_extract_const( pwd_data, &pwd, &pwdlen, NULL);    // expand the pkbuf_t
    if (key[klen - 1] != '\0')
        goto no_pem;   // Not null terminated so it cannot be a pem string

    if ( (p = strstr((char*)key,"-----BEGIN ")) == NULL) 
        goto no_pem;   // No PEM begin string 
    if ( (strstr(p+1,"KEY-----")) == NULL) 
        goto no_pem;   // No PEM end string 
    // 
    // This is a PEM file 
    // Find the algorithm 
    p = strstr(p," ") + 1; 
    pktype = MBEDTLS_PK_NONE;
    if ( strncmp(p, "RSA ",4) == 0) {   // -----BEGIN RSA ..." 
        alg_str = "RSA ";   // NOTE: The space in the string is required
        pktype = MBEDTLS_PK_RSA;
    }
    else if ( strncmp(p, "EC ",3) == 0) { // -----BEGIN EC ..."
        alg_str = "EC ";
        pktype = MBEDTLS_PK_ECKEY; 
    }
    else if ( strncmp(p, "ENCRYPTED ",10) == 0) { // -----BEGIN ENCRYPTED ..."
        alg_str = "ENCRYPTED ";
        pktype = PKTYPE_DER_ENCRYPTED;
    }
    else {
        alg_str = "";
        pktype = PKTYPE_DER_PKCS8;
    }

    if ( (pktype != PKTYPE_DER_PKCS8) && (pktype != MBEDTLS_PK_NONE) )
    {
        if( (p = strstr(p+1," ")) == NULL) {
            rc = MBEDTLS_ERR_PEM_BAD_INPUT_DATA; 
            goto fail_pem;                 // No PEM end string 
        }
        p += 1; 
    }
    if ( strncmp(p, "PUBLIC",6) == 0)          // -----BEGIN xxx PUBLIC KEY-----" 
        id_str = "PUBLIC";
    else if ( strncmp(p, "PRIVATE",7) == 0)    // -----BEGIN xxx PRIVATE KEY-----" 
        id_str = "PRIVATE";
    else 
        goto no_pem;   // No useable header 

    snprintf(header, sizeof(header),"-----BEGIN %s%s KEY-----", alg_str, id_str);
    snprintf(footer, sizeof(footer),"-----END %s%s KEY-----", alg_str, id_str);
    // LOGD("%s(): Check for header:'%s' and footer:'%s'\n", __func__, header, footer);

    // Check if this is an RSA private key
    if ( (rc = mbedtls_pem_read_buffer(&pem, header, footer, key, pwd, pwdlen, &len)) != SUCCESS) 
        goto fail_pem;                 // PEM format cannot be parsed 

    // LOGD("%s(): Check for header is SUCCESS\n", __func__);
    // Successfully converted PEM to DER. The DER data is in pem.buf 
    pkbuf_init(der_data, pem.buf, pem.buflen, pem.buflen);
    *pktype_out = pktype;
    pem.buf = NULL;  // Somewhat cludgy, prevents freeing the memory in 'der_data' 
    mbedtls_pem_free(&pem);
    return SUCCESS;

    // No supported PEM format found 
no_pem:
    rc = 0;    // Distinguish between bad PEM and no PEM. 
fail_pem:
    if ( rc != 0) {
        LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    }
    pkbuf_init(der_data, NULL, 0, 0); // set der buffer pointer to NULL 
    *pktype_out = MBEDTLS_PK_NONE;
    mbedtls_pem_free(&pem);
    return rc;
}
#else 
  // Stub the pem2der_key() function 
  #define pem2der_key(a,b,c,d)   0
#endif // if defined(MBEDTLS_PEM_PARSE_C)

/******************************************************************************
 * Description: Check to see if the public key has a hybrid key header 
 *
 * Arguments:   idata    - input data 
 *              der_olen - the length of the first DER structure 
 * 
 * result:      
 *****************************************************************************/
static int pkey_check_hybrid_pubkey_header( pkbuf_t *idata, size_t *hdr_len, size_t *der_olen )
{
    mbedtls_asn1_buf  alg_params; 
    pktype_e          pktype;    
    uint8_t          *p, *end;  
    size_t            len;      
    int               rc, version;       

    /*---------------------Code ----------------------------------------------*/
    p   = (uint8_t *)idata->buf; 
    end = p + idata->size; 

    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto fail;

    SET_VAL_SAFE( der_olen, (p - idata->buf) + len); 
    end = p + len;

    if( ( rc = mbedtls_asn1_get_int( &p, end, &version ) ) != SUCCESS)
         goto fail;
     if( version != 1 )
         goto fail_bad_input; 

    // Get the algorithm information from the ANS1 data
    if( ( rc = pk_get_pk_alg( &p, end, &pktype, &alg_params ) ) != 0 )
        goto fail;
    if (pktype != MBEDTLS_PK_MULTI)
        goto fail_bad_input; 

    *hdr_len = p - idata->buf; 

    LOGD("%s(): Found a hybrid public key header, hdr_len=%d\n", __func__, (int)*hdr_len);
    return SUCCESS; 

fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
fail:  // No hybrid public key header  
    SET_VAL_SAFE( der_olen, 0); 
    return rc;
}
/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Glocal Functions -----------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/******************************************************************************
 * Description: Setup a full key context 
 *
 * Arguments:   pkfull   - The 'full' pk context. It must have been initialized
 *              p        - the position in the ASN.1 data
 *              end      - end
 *              der_olen - the length of the first DER structure 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
int pkey_parse_subpubkey( pkfull_t *pkfull, uint8_t **p, const uint8_t *end,  size_t *der_olen )
{
    asn1buf_t    alg_params;
    pktype_e     pktype = MBEDTLS_PK_NONE;
    uint8_t     *start;
    size_t       len; 
    int          rc = LIB_ERROR;

    /*---------------------Code ----------------------------------------------*/
    if ( p == NULL || *p == NULL || end == NULL || pkfull == NULL)
        goto fail_bad_input;

    start = *p; 
    if( ( rc = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto fail_asn1;

    SET_VAL_SAFE( der_olen, (*p - start) + len); 
    end = *p + len;
    
    // Get the algorithm information from the ANS1 data
    if( ( rc = pk_get_pk_alg( p, end, &pktype, &alg_params ) ) != 0 )
        goto fail;

    if( ( rc = mbedtls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        goto fail_asn1;

    if( *p + len != end )
        goto fail_mismatch;

    if ( (pktype > MBEDTLS_PK_NONE) &&( pktype < MBEDTLS_PK_LAST) ) 
    {
        // Found a correct subpubkey pkey algorithm. Now we can import that key 
        pkbuf_t idata; 
        pkbuf_init(&idata, *p, len, 0); 
        if( (rc = pk_import_pub_key( pkfull, &idata, PK_TARGET_PUB, pktype, (void*)&alg_params, NULL)) != SUCCESS)
            goto fail;
        goto end; // We are done 
    }
    
    // If we get here that means that the parsing failed

    // --- Error handling ---
    rc = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG; goto fail;
fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_asn1:
    rc = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_INVALID_PUBKEY, rc ); goto fail; 
fail_mismatch:
    rc = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_INVALID_PUBKEY, MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    SET_VAL_SAFE( der_olen, 0); 
    pk_pkfull_clean( pkfull );
end: 
    return rc;
}


/*----------------------------------------------------------------------------
 * Parse a public key from an ssl context with key prototype info 
 * ---------------------------------------------------------------------------*/
int pkey_parse_pubkey_ssl( pktop_t *pktop, pktarget_e target, hybpk_t hybpk_alg, void* alg_info,  uint8_t **p, const uint8_t *end )
{
    struct pkfull_s *pkfull = NULL;
    pktype_e         pktype; 
    pkbuf_t          kdata;
    size_t           olen; 
    int              rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( hybpk_alg > 256 ) // A hybrid key uses a public key with oids 
        return mbed_pk_parse_subpubkey( (mbed_pktop_t *)pktop, p, end); 
     
    pktype = (pktype_e)hybpk_alg; // Single key means hybrid type is a single algorithm 
    if ((pkfull = (struct pkfull_s *)mbed_calloc( 1, sizeof(struct pkfull_s) )) == NULL)
        goto fail_malloc;
    pkfull->pktop = pktop; 

    pkbuf_init( &kdata, *p, (size_t)(end - *p), 0);
    if( ( rc = pk_import_pub_key(pkfull, &kdata, target, pktype, alg_info, &olen)) != 0)
        goto fail; 

    *p += olen; 

    // Parse successful. Add the parsed key to the top key context
    if( (rc = pkey_add_fullkey_to_list( pktop, pkfull)) != SUCCESS)
        goto fail; 
    return SUCCESS; 

        // --- Error handling ---
fail_malloc:
    rc = MBEDTLS_ERR_PK_ALLOC_FAILED;
fail:
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    return rc;
}



/******************************************************************************
 * Description: Parse public or private key data (PEM or DER) 
 *
 * Arguments:   pktop    - Key top context 
 *              kdata    - key data 
 *              pwd_data - pwd data
 *              pktype   - single key type 
 *              der_olen - container for number of kdata bytes consumed  
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int pk_import_single_key( pktop_t *pktop, pktarget_e target, pkbuf_t *kdata, pkbuf_t *pwd_data, pktype_e pktype, size_t *der_olen)
{
    struct pkfull_s *pkfull = NULL;
    int              rc; 

    /*---------------------Code ----------------------------------------------*/
    if( (pkfull = (struct pkfull_s *)mbed_calloc(1, sizeof(struct pkfull_s)) ) == NULL) 
        goto fail_malloc;
    pkfull->pktop = (pktop_t*)pktop; 

    // parse the DER formatted key
    if (target == PK_TARGET_PRV) 
    {
        pkfull->is_pub = FALSE;
        rc = parse_der_prv_key( pkfull, kdata, pwd_data, pktype, der_olen);
    } 
    else 
    {
        pkfull->is_pub = TRUE;
        rc = parse_der_pub_key( pkfull, kdata, pktype, der_olen);
    }
    if (rc != 0 )
        goto fail; 

    // Parse successful. Add the parsed key to the top key context
    if( (rc = pkey_add_fullkey_to_list( pktop, pkfull)) != SUCCESS)
        goto fail; 
    return SUCCESS;

     // --- Error handling --- 
fail_malloc:
    rc = MBEDTLS_ERR_PK_ALLOC_FAILED; 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    pkfull = pkey_free_pkfull(pkfull); 
    return rc; 
}


/******************************************************************************
 * Description: Parse public or private key data (PEM or DER) 
 *
 * Arguments:   pkfull   - The 'full' pk context. It must have been initialized
 *              target   - public or private key 
 *              kdata    - keey data
 *              pwddata  - password data 
 * 
 * result:      SUCCESS=0 / FAILURE
 *****************************************************************************/
static int pk_parse_key( pktop_t *pktop, pktarget_e target, pkbuf_t *kdata, pkbuf_t *pwd_data)
{
    pktype_e         pktype  = MBEDTLS_PK_NONE;     
    pkbuf_t          single_kdata; 
    pkbuf_t          der_result = {0};  
    uint8_t         *buf;                   
    size_t           buf_len, offs = 0, hdr_len;
    size_t           der_olen;         // output length of the parsed DER key 
    int              rc;                   


    /*---------------------Code ----------------------------------------------*/
    if ( pktop == NULL || kdata == NULL || kdata->size == 0 )
        goto fail_bad_input;

    if( (rc = pem2der_key( kdata, pwd_data, &pktype, &der_result)) < 0)
        goto fail; 
    
    if (der_result.buf == NULL || der_result.size == 0) 
    {  // No PEM to DER conversion
        buf     = (uint8_t*)kdata->buf; 
        buf_len = kdata->size;
    } 
    else 
    {   // PEM to DER conversion
        buf     = (uint8_t*)der_result.buf; 
        buf_len = der_result.size; 
    }

    pkbuf_init( &single_kdata, buf, buf_len, 0);   
    if( pkey_check_hybrid_pubkey_header( &single_kdata, &hdr_len, &der_olen) == SUCCESS) 
    {
        // This DER has a hybrid public key header. 
        if ( der_olen != buf_len) // The ASN1 tag length (der_olen) must match the buffer size (buf_len) 
            goto fail_bad_key; 
        offs += hdr_len; 
        if (offs >= buf_len)
            goto fail_bad_key;    // No actual key data 
    }
    // Loop through all the individual keys in the hybrid key 
    while( offs < buf_len)
    {
        pkbuf_init( &single_kdata, buf + offs, buf_len - offs, 0);   
        if ((rc = pk_import_single_key(pktop, target, &single_kdata, pwd_data, pktype, &der_olen)) != SUCCESS) 
            goto fail;
        offs += der_olen; 
    }
    der_result.buf = mbed_free( (void*)der_result.buf);  //free the DER buffer allocated in pem2der_prv_key()
    return SUCCESS; 

    // --- Error handling --- 
fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail; 
fail_bad_key: 
    rc = MBEDTLS_ERR_PK_INVALID_PUBKEY; 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    mbed_pk_free( (mbed_pktop_t*)pktop );      // bad key data -> cleanup the whole context 
    der_result.buf = mbed_free( (void*)der_result.buf);   //free the DER buffer allocated in pem2der_prv_key()
    return rc; 
}


/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
 *   Parse a private key
 * ---------------------------------------------------------------------------*/
int mbed_pk_parse_prvkey(mbed_pktop_t *pktop_ref, const uint8_t *key, size_t klen, const uint8_t *pwd, size_t pwdlen)
{
    pktop_t   *pktop = (pktop_t *)pktop_ref;  
    pkbuf_t    kdata, pwd_data;

    /*---------------------Code ----------------------------------------------*/
    if (pktop->is_pub != FALSE)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    pkbuf_init( &kdata, key, klen, 0 );
    pkbuf_init( &pwd_data, pwd, pwdlen, 0);
    return pk_parse_key( pktop, PK_TARGET_PRV, &kdata, &pwd_data );
}


/*----------------------------------------------------------------------------
 * Parse a public key
 * ---------------------------------------------------------------------------*/
int mbed_pk_parse_pubkey( mbed_pktop_t *pktop_ref, const uint8_t *key, size_t klen )
{
    pktop_t  *pktop = (pktop_t *)pktop_ref;  // Need a non-const context here
    pkbuf_t   kdata; 


    /*---------------------Code ----------------------------------------------*/
    if ((pktop->num_keys != 0) && (pktop->is_pub == FALSE))
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA; 

    pkbuf_init( &kdata, key, klen, 0 );
    return pk_parse_key(pktop, PK_TARGET_PUB, &kdata, NULL); 
}

/*----------------------------------------------------------------------------
 * Parse a public key in subpub DER format 
 * ---------------------------------------------------------------------------*/
int mbed_pk_parse_subpubkey(mbed_pktop_t *pktop_ref, uint8_t **p, const uint8_t *end) 
{
    pktop_t    *pktop = (pktop_t *)pktop_ref;
    pkbuf_t     kdata;
    pktype_e    pktype;
    uint8_t    *hybrid_end;
    size_t      der_olen, klen, single_keylen, hdr_len;
    int         rc;

    /*---------------------Code ----------------------------------------------*/
    if (pktop_ref == NULL || p == NULL || *p == NULL || end == NULL)
        goto fail_bad_input;

    if ((pktop->num_keys != 0) && (pktop->is_pub == FALSE))
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA; 

    pktype        = PKTYPE_SUBPUBKEY;
    klen          = (size_t)(end - *p);
    pkbuf_init( &kdata, *p, klen, 0 );
    if (pkey_check_hybrid_pubkey_header( &kdata, &hdr_len, &der_olen ) == SUCCESS)
    {
        // This DER has a hybrid public key header. Loop through all the keys
        hybrid_end = *p + der_olen;
        if (hybrid_end > end)
            goto fail_bad_key; // Hybrid key is larger than the data in the buffer
        *p  += hdr_len;
        while (TRUE)
        {
            klen = (size_t)(hybrid_end - *p);
            if (klen <= 0)
                break;
            pkbuf_init( &kdata, *p, klen, 0 );
            if ((rc = pk_import_single_key( pktop, PK_TARGET_PUB, &kdata, NULL, pktype, &single_keylen )) != SUCCESS)
                goto fail;
            *p += single_keylen;
        }
    }
    else
    {
        if ((rc = pk_import_single_key( pktop, PK_TARGET_PUB, &kdata, NULL, pktype, &der_olen )) != SUCCESS)
            goto fail;
        *p += der_olen;
    }
    return SUCCESS;

    // --- Error handling ---
fail_bad_input:
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; goto fail;
fail_bad_key:
    rc = MBEDTLS_ERR_PK_INVALID_PUBKEY;
fail:
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    return rc;
}


/*----------------------------------------------------------------------------
 * Parse a public key from an ssl context 
 * ---------------------------------------------------------------------------*/
int mbed_pk_parse_pubkey_ssl( mbed_pktop_t *pktop_ref, pktarget_e target, hybpk_t hybpk_alg, uint8_t **p, const uint8_t *end)
{
    // --- this call does not provide algorithm information. 
    // --- The assumption is the SSL pubkey data provides the relevant alg info. 
    return pkey_parse_pubkey_ssl((pktop_t *)pktop_ref, target, hybpk_alg, NULL, p, end); 
}


#if defined(MBEDTLS_FS_IO)
/*----------------------------------------------------------------------------
 * Load all data from a file into a given buffer.
 *
 * The file is expected to contain either PEM or DER encoded data.
 * A terminating null byte is always appended. It is included in the announced
 * length only if the data looks like it is PEM encoded.
 * ---------------------------------------------------------------------------*/
int mbed_pk_load_file( const char *path, uint8_t **buf, size_t *n )
{
    FILE  *f = NULL;
    long   size;
    int    rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( path == NULL || buf == NULL || n == NULL) 
        goto fail_bad_input;
    
    if( ( f = fopen( path, "rb" ) ) == NULL )
        goto fail_io; 

    fseek( f, 0, SEEK_END );
    if( ( size = ftell( f ) ) == -1 )
        goto fail_io; 
    fseek( f, 0, SEEK_SET );

    *n = (size_t) size;

    if( *n + 1 == 0 || ( *buf = mbed_calloc( 1, *n + 1 ) ) == NULL )
        goto fail_alloc; 

    if( fread( *buf, 1, *n, f ) != *n )
    {
        mbedtls_platform_zeroize( *buf, *n );
        mbed_free( *buf );
        goto fail_io;
    }
    fclose( f );

    (*buf)[*n] = '\0';
    if( strstr( (const char *) *buf, "-----BEGIN " ) != NULL )
        ++*n;
    return SUCCESS;


    // --- Error handling --- 
fail_alloc:
    rc = MBEDTLS_ERR_PK_ALLOC_FAILED; goto fail;
fail_io:
    rc = MBEDTLS_ERR_PK_FILE_IO_ERROR; goto fail; 
fail_bad_input:
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA; 
fail: 
    if (f != NULL) 
        fclose(f);
    return rc;
}


/* ---------------------------------------------------------------------------
 *  * Load and parse a private key
 * ---------------------------------------------------------------------------*/
int mbed_pk_parse_prv_keyfile(mbed_pktop_t *pktop_ref, const char *path, const char *pwd)
{
    pktop_t  *pktop = (pktop_t *)pktop_ref;
    size_t    n;
    uint8_t  *buf = NULL;
    int       len, rc = LIB_ERROR;


    /*---------------------Code ----------------------------------------------*/
    if (pktop == NULL || path == NULL)
        goto fail_bad_input;

    if ((rc = mbed_pk_load_file(path, &buf, &n)) != 0)
        goto fail;

    if (pwd == NULL)
        len = 0;
    else
        len = strlen(pwd);
    rc = mbed_pk_parse_prvkey((void*)pktop, buf, n, (const uint8_t *)pwd, len);
    goto cleanup; // SUCCESS


    // --- Error handling ---
fail_bad_input:
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
cleanup:
    if (buf != NULL)
    {
        mbedtls_platform_zeroize(buf, n);
        mbed_free(buf);
    }
    return rc;
}


/* ---------------------------------------------------------------------------
 *  Load and parse a public key
 * ---------------------------------------------------------------------------*/
int mbed_pk_parse_pub_keyfile( mbed_pktop_t *pktop_ref, const char *path )
{
    pktop_t  *pktop = (pktop_t *)pktop_ref;
    int       rc = LIB_ERROR;
    size_t    n;
    uint8_t  *buf = NULL;


    /*---------------------Code ----------------------------------------------*/
    if (  pktop == NULL || path == NULL ) 
        goto fail_bad_input;

    if( ( rc = mbed_pk_load_file( path, &buf, &n ) ) != 0 )
        goto fail;

    if( (rc = mbed_pk_parse_pubkey( (void*)pktop, buf, n )) != SUCCESS) 
        goto fail;
    goto cleanup;  // SUCCESS 

    // --- Error handling --- 
fail_bad_input:
    rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA; 
fail: 
cleanup:
    if ( buf != NULL) {
        mbedtls_platform_zeroize(buf, n);
        mbed_free( buf );
    }
    return rc;
}
#endif /* MBEDTLS_FS_IO */

#endif /* MBEDTLS_PK_PARSE_C */
