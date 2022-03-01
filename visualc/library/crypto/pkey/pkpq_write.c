/*
 *  Public Key layer for writing key files and structures
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

#if defined(MBEDTLS_PK_WRITE_C)

#include "mbedtls/pk.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "pkpq_write.h"
#include "crypto_util.h"

#define LOGS_PREFIX "  PK_WRITE: "
#include "crypto_common.h"

#include <string.h>

#if defined(MBEDTLS_RSA_C)
 #include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
 #include "mbedtls/bignum.h"
 #include "mbedtls/ecp.h"
 #include "mbedtls/platform_util.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
 #include "mbedtls/ecdsa.h"
#endif
#if defined(MBEDTLS_PEM_WRITE_C)
 #include "mbedtls/pem.h"
#endif


//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define ASN1_CHK_ADD(g, f)              \
    do                                  \
    {                                   \
        if( ( rc = (f) ) < 0 )          \
            goto fail;                  \
        else                            \
            (g) += rc;                  \
    } while( 0 )



/* ---------------------------------------------------------------------------
 *  Convert a key top context to DER formatted data 
 * ---------------------------------------------------------------------------*/
static int pk_write_key_der( mbed_pktop_t *pktop_ref, pktarget_e target, uint8_t *buf, size_t size )
{
    pktop_t  *pktop = (pktop_t *)pktop_ref;
    pkfull_t *pkfull;
    pkbuf_t   odata; 
    size_t    len = 0;  
    int       i, rc; 


    /*---------------------Code ----------------------------------------------*/
    if (pktop_ref == NULL ||  buf == NULL || size == 0)
        goto fail_bad_data;

    // Loop through all keys in the hybrid key context 
    // The DER writing occurs from back to front, so start at the last key
    for (i = pktop->num_keys - 1; i >= 0; i--)
    {
        if (len >= size )
            return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; 

        pkfull = pktop->pkfull_list[i];

        // call algorithm export function (xx_export_wrap: e.g. ec_export_wrap or rsa_export_wrap)  
        if (pkfull->pkinfo->export_func == NULL )
            goto fail_unavailable; 

        // DER writes from end to begin so the start of the buffer stays the same 
        pkbuf_init(&odata, buf, size-len, 0); 

        if (pktop->num_keys > 1 && (target == PK_TARGET_PUBSSL) )
            target = PK_TARGET_PUB; // A hybrid key adds the OID info (for now) 

        if( (rc = pkfull->pkinfo->export_func(pkfull->pkctx, target, PK_EXPORT_DER, &odata)) != SUCCESS)
            goto fail; 

        len += odata.iolen;
        // printf("%s(): Wrote %d DER bytes\n", __func__, (int)odata.olen); 
    }
    if ((pktop->num_keys > 1) && ((target == PK_TARGET_PUB) || (target == PK_TARGET_PUBSSL)))
    { 
        // Add a hybrid length field to the public key 
        uint8_t      *p, *start;
        const char   *hybrid_oid;
        size_t        oid_len; 
        int           version; 

        if( ( rc = mbedtls_oid_get_oid_by_pk_alg(MBEDTLS_PK_MULTI, &hybrid_oid, &oid_len )) != 0 )
            goto fail; 

        start = buf;  
        p     = buf + size - len; 
        // Write OID 
        ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&p, start, hybrid_oid, oid_len, 0));

        // Write version and length
        version = 1; 
        ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, start, version));
        ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
        ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    }
    // printf("%s(): Wrote %d DER bytes\n", __func__, (int)len); 
    return (int)len; 


    // --- Error handling --- 
fail_unavailable:
    rc = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE; goto fail; 
fail_bad_data: 
    rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

#if defined(MBEDTLS_PEM_WRITE_C)
/* ---------------------------------------------------------------------------
 *  Convert a key top context to PEM formatted data
 *  target: selects the pulbic/private key 
 * ---------------------------------------------------------------------------*/
int pk_write_key_pem( mbed_pktop_t *pktop_ref, pktarget_e target, uint8_t *buf, size_t size )
{
     pktop_t     *pktop = (pktop_t *)pktop_ref;
     uint8_t      output_buf[PRV_DER_MAX_BYTES], *der_start; 
     const char  *pem_header, *pem_footer;
     size_t       der_len, olen = 0;
     int          idx = 0, rc = LIB_ERROR;


     /*---------------------Code ----------------------------------------------*/
     if ( pktop_ref == NULL ||  buf == NULL || size == 0)
         goto fail_bad_input;

     if ((rc = pk_write_key_der((void *)pktop, target, output_buf, sizeof(output_buf))) < 0)
         goto fail;
     der_len = rc; 

     if (target == PK_TARGET_PRV)
     {
         pem_header = PEM_BEGIN_PRIVATE_KEY;
         pem_footer = PEM_END_PRIVATE_KEY;
     }
     else if (target == PK_TARGET_PUB)
     {
         pem_header = PEM_BEGIN_PUBLIC_KEY;
         pem_footer = PEM_END_PUBLIC_KEY;
     }
     else 
         goto fail_bad_input; 

     buf[size-1] = 0x0;  // Null terminate 
     idx = snprintf((char*)buf, size,"----KEY TYPE %s PKCS8----\n", mbed_pk_get_hybrid_name(pktop_ref));  

     der_start = output_buf + sizeof(output_buf) - rc;  // find the start of the DER data 
     if( ( rc = mbedtls_pem_write_buffer( pem_header, pem_footer, der_start, der_len, buf+idx, size-idx, &olen ) ) != 0 )
         goto fail; 
     return olen;

     // --- Error handling --- 
fail_bad_input:
     rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
fail:
     LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
     return rc; 
}
#endif /* MBEDTLS_PEM_WRITE_C */

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
 *  Convert a private key top context to DER formatted data 
 * ---------------------------------------------------------------------------*/
int mbed_pk_write_key_der( mbed_pktop_t *pktop_ref, uint8_t *buf, size_t size )
{
    return pk_write_key_der(pktop_ref, PK_TARGET_PRV, buf, size); 
}

/* ---------------------------------------------------------------------------
 *  Convert a public key top context to DER formatted data 
 * ---------------------------------------------------------------------------*/
int mbed_pk_write_pubkey_der( mbed_pktop_t *pktop_ref, uint8_t *buf, size_t size )
{
    return pk_write_key_der(pktop_ref, PK_TARGET_PUB, buf, size); 
}

/* ---------------------------------------------------------------------------
 *  Convert a public key top context to DER formatted data 
 * ---------------------------------------------------------------------------*/
int mbed_pk_write_pubkey_ssl( mbed_pktop_t *pktop_ref, uint8_t *buf, size_t size, size_t *olen)
{
    int publen;

    *olen = 0; 
    publen = pk_write_key_der(pktop_ref, PK_TARGET_PUBSSL, buf, size); 
    if ( publen < 0) 
        return publen;  // Contains error code 

    //--- DER writes from end to beginning, so move the data to the beginning 
    memmove( buf, buf + size - publen, publen); 
    *olen = publen; 
    return SUCCESS; 
}

#if defined(MBEDTLS_PEM_WRITE_C)
/* ---------------------------------------------------------------------------
 *  Convert a private key top context to PEM formatted data 
 * ---------------------------------------------------------------------------*/
int mbed_pk_write_key_pem( mbed_pktop_t *pktop_ref, uint8_t *buf, size_t size )
{
    return pk_write_key_pem(pktop_ref, PK_TARGET_PRV, buf, size); 
}

/* ---------------------------------------------------------------------------
 *  Convert a public key top context to PEM formatted data 
 * ---------------------------------------------------------------------------*/
int mbed_pk_write_pubkey_pem( mbed_pktop_t *pktop_ref, uint8_t *buf, size_t size )
{
    return pk_write_key_pem(pktop_ref, PK_TARGET_PUB, buf, size); 
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_PK_WRITE_C */
