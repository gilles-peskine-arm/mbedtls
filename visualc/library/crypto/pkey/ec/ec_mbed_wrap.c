#include "common.h"

#if defined(MBEDTLS_PK_C)
#if defined(MBEDTLS_ECP_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <limits.h>
#include <stdint.h>
#include <string.h>


// #include "mbedtls/error.h"
//#include "pkpq_wrap.h"
#include "pkpq.h"
#include "crypto_util.h"

#define LOGS_PREFIX "    PK_EC: "
#include "crypto_common.h"

#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#if defined(MBEDTLS_ECDSA_C)
  #include "mbedtls/ecdsa.h"
#endif
#if defined(MBEDTLS_PLATFORM_C)
  #include "mbedtls/platform.h"
#endif
// #include "../3rdparty/everest/include/everest/everest.h"


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

#define MPI_CHK(f)               \
    do                           \
    {                            \
        if( ( rc = (f) ) != 0 )  \
            goto fail;           \
    } while( 0 )

//----------------------------------------------------------------------------
//----------------- Constant variables ---------------------------------------
//----------------------------------------------------------------------------
static const uint8_t oid_data[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}; 
static pkbuf_t       ec_oid = {oid_data, oid_data, sizeof(oid_data), 0}; 

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- Local Functions ------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/

/* Minimally parse an ECParameters buffer to and mbedtls_asn1_buf
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 * }
 */
static int get_ecparams( uint8_t **p, const uint8_t *end, mbedtls_asn1_buf *params )
{
    int rc = LIB_ERROR;

    if ( end - *p < 1 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_OUT_OF_DATA ) );

    /* Tag may be either OID or SEQUENCE */
    params->tag = **p;
    if( params->tag != MBEDTLS_ASN1_OID
#if defined(MBEDTLS_PK_PARSE_EC_EXTENDED)
            && params->tag != ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE )
#endif
            )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) );
    }

    if( ( rc = mbedtls_asn1_get_tag( p, end, &params->len, params->tag ) ) != 0 )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc ) );
    }

    params->p = *p;
    *p += params->len;

    if( *p != end )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH ) );

    return SUCCESS;
}


#if defined(MBEDTLS_PK_PARSE_EC_EXTENDED)
/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and (mostly) fill the group with it.
 * WARNING: the resulting group should only be used with
 * group_id_from_specified(), since its base point may not be set correctly
 * if it was encoded compressed.
 *
 *  SpecifiedECDomain ::= SEQUENCE {
 *      version SpecifiedECDomainVersion(ecdpVer1 | ecdpVer2 | ecdpVer3, ...),
 *      fieldID FieldID {{FieldTypes}},
 *      curve Curve,
 *      base ECPoint,
 *      order INTEGER,
 *      cofactor INTEGER OPTIONAL,
 *      hash HashAlgorithm OPTIONAL,
 *      ...
 *  }
 *
 * We only support prime-field as field type, and ignore hash and cofactor.
 */
static int group_from_specified( const mbedtls_asn1_buf *params, mbedtls_ecp_group *grp )
{
    int rc = LIB_ERROR;
    uint8_t *p = params->p;
    const uint8_t * const end = params->p + params->len;
    const uint8_t *end_field, *end_curve;
    size_t len;
    int ver;

    /* SpecifiedECDomainVersion ::= INTEGER { 1, 2, 3 } */
    if( ( rc = mbedtls_asn1_get_int( &p, end, &ver ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc ) );

    if( ver < 1 || ver > 3 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );

    /*
     * FieldID { FIELD-ID:IOSet } ::= SEQUENCE { -- Finite field
     *       fieldType FIELD-ID.&id({IOSet}),
     *       parameters FIELD-ID.&Type({IOSet}{@fieldType})
     * }
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( rc );

    end_field = p + len;

    /*
     * FIELD-ID ::= TYPE-IDENTIFIER
     * FieldTypes FIELD-ID ::= {
     *       { Prime-p IDENTIFIED BY prime-field } |
     *       { Characteristic-two IDENTIFIED BY characteristic-two-field }
     * }
     * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end_field, &len, MBEDTLS_ASN1_OID ) ) != 0 )
        return( rc );

    if( len != MBEDTLS_OID_SIZE( MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD ) ||
        memcmp( p, MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD, len ) != 0 )
    {
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
    }

    p += len;

    /* Prime-p ::= INTEGER -- Field of size p. */
    if( ( rc = mbedtls_asn1_get_mpi( &p, end_field, &grp->P ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc ) );

    grp->pbits = mbedtls_mpi_bitlen( &grp->P );

    if( p != end_field )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH ) );

    /*
     * Curve ::= SEQUENCE {
     *       a FieldElement,
     *       b FieldElement,
     *       seed BIT STRING OPTIONAL
     *       -- Shall be present if used in SpecifiedECDomain
     *       -- with version equal to ecdpVer2 or ecdpVer3
     * }
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( rc );

    end_curve = p + len;

    /*
     * FieldElement ::= OCTET STRING
     * containing an integer in the case of a prime field
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end_curve, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 ||
        ( rc = mbedtls_mpi_read_binary( &grp->A, p, len ) ) != 0 )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc ) );
    }

    p += len;

    if( ( rc = mbedtls_asn1_get_tag( &p, end_curve, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 ||
        ( rc = mbedtls_mpi_read_binary( &grp->B, p, len ) ) != 0 )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc ) );
    }

    p += len;

    /* Ignore seed BIT STRING OPTIONAL */
    if( ( rc = mbedtls_asn1_get_tag( &p, end_curve, &len, MBEDTLS_ASN1_BIT_STRING ) ) == 0 )
        p += len;

    if( p != end_curve )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH ) );

    /*
     * ECPoint ::= OCTET STRING
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc ) );

    if( ( rc = mbedtls_ecp_point_read_binary( grp, &grp->G,
                                      ( const uint8_t *) p, len ) ) != 0 )
    {
        /*
         * If we can't read the point because it's compressed, cheat by
         * reading only the X coordinate and the parity bit of Y.
         */
        if( rc != MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ||
            ( p[0] != 0x02 && p[0] != 0x03 ) ||
            len != mbedtls_mpi_size( &grp->P ) + 1 ||
            mbedtls_mpi_read_binary( &grp->G.X, p + 1, len - 1 ) != 0 ||
            mbedtls_mpi_lset( &grp->G.Y, p[0] - 2 ) != 0 ||
            mbedtls_mpi_lset( &grp->G.Z, 1 ) != 0 )
        {
            return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
        }
    }

    p += len;

    /*
     * order INTEGER
     */
    if( ( rc = mbedtls_asn1_get_mpi( &p, end, &grp->N ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc ) );

    grp->nbits = mbedtls_mpi_bitlen( &grp->N );

    /*
     * Allow optional elements by purposefully not enforcing p == end here.
     */

    return SUCCESS;
}


/* ---------------------------------------------------------------------------
 * Find the group id associated with an (almost filled) group as generated by
 * group_from_specified(), or return an error if unknown. 
 * ---------------------------------------------------------------------------*/
static int group_id_from_group( const mbedtls_ecp_group *grp, mbedtls_ecp_group_id *grp_id )
{
    const mbedtls_ecp_group_id  *id;
    mbedtls_ecp_group            ref;
    int                          rc = 0;

    /*---------------------Code ----------------------------------------------*/
    mbedtls_ecp_group_init( &ref );

    for( id = mbedtls_ecp_grp_id_list(); *id != MBEDTLS_ECP_DP_NONE; id++ )
    {
        /* Load the group associated to that id */
        mbedtls_ecp_group_free( &ref );
        MPI_CHK( mbedtls_ecp_group_load( &ref, *id ) );

        /* Compare to the group we were given, starting with easy tests */
        if( grp->pbits == ref.pbits && grp->nbits == ref.nbits &&
            mbedtls_mpi_cmp_mpi( &grp->P, &ref.P ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->A, &ref.A ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->B, &ref.B ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->N, &ref.N ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->G.X, &ref.G.X ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->G.Z, &ref.G.Z ) == 0 &&
            /* For Y we may only know the parity bit, so compare only that */
            mbedtls_mpi_get_bit( &grp->G.Y, 0 ) == mbedtls_mpi_get_bit( &ref.G.Y, 0 ) )
        {
            break;
        }
    }
    *grp_id = *id;
    if( *id == MBEDTLS_ECP_DP_NONE) 
        goto fail_unavailable;  
    rc = SUCCESS;
    goto cleanup; 

    // --- Error handling ---
fail_unavailable:
    rc = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
cleanup: 
    mbedtls_ecp_group_free( &ref );
    return( rc );
}

/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and find the associated group ID
 */
static int group_id_from_specified( const mbedtls_asn1_buf *params, mbedtls_ecp_group_id *grp_id )
{
    int rc = LIB_ERROR;
    mbedtls_ecp_group grp;

    mbedtls_ecp_group_init( &grp );

    if( ( rc = group_from_specified( params, &grp ) ) != 0 )
        goto cleanup;

    rc = group_id_from_group( &grp, grp_id );

cleanup:
    mbedtls_ecp_group_free( &grp );

    return( rc );
}
#endif /* MBEDTLS_PK_PARSE_EC_EXTENDED */


 /*
 * Use EC parameters to initialise an EC group
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 */
static int use_ecparams( const mbedtls_asn1_buf *params, mbedtls_ecp_group *grp )
{
    int rc = LIB_ERROR;
    mbedtls_ecp_group_id grp_id;

    if( params->tag == MBEDTLS_ASN1_OID )
    {
        if( mbedtls_oid_get_ec_grp( params, &grp_id ) != 0 )
            return( MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE );
    }
    else
    {
      #if defined(MBEDTLS_PK_PARSE_EC_EXTENDED)
        if( ( rc = group_id_from_specified( params, &grp_id ) ) != 0 )
            return( rc );
      #else
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
      #endif
    }

    /*
     * grp may already be initilialized; if so, make sure IDs match
     */
    if( grp->id != MBEDTLS_ECP_DP_NONE && grp->id != grp_id )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );

    if( ( rc = mbedtls_ecp_group_load( grp, grp_id ) ) != 0 )
        return( rc );

    return SUCCESS;
}


/*
 * EC public key is an EC point
 *
 * The caller is responsible for clearing the structure upon failure if
 * desired. Take care to pass along the possible ECP_FEATURE_UNAVAILABLE
 * return code of mbedtls_ecp_point_read_binary() and leave p in a usable state.
 */
static int get_ecpubkey( uint8_t **p, const uint8_t *end, eckey_t *key )
{
    int rc = LIB_ERROR;

    if( ( rc = mbedtls_ecp_point_read_binary( &key->grp, &key->Q, (const uint8_t *) *p, end - *p ) ) == 0 )
    {
        rc = mbedtls_ecp_check_pubkey( &key->grp, &key->Q );
    }

    /*
     * We know mbedtls_ecp_point_read_binary consumed all bytes or failed
     */
    *p = (uint8_t *) end;

    return( rc );
}


/******************************************************************************
 *
 * Description: Parse a SEC1 encoded private EC key
 *
 * Arguments:   eckey    - EC key context 
 *              key      - DER key data
 *              klen     - size of the DER key data 
 *              der_olen - container for the parse DER size  
 *
 * result:      SUCCESS=0 / FAILURE
 *
 *****************************************************************************/
static int parse_key_sec1_der( eckey_t *eckey, const uint8_t *key, size_t klen, size_t *der_olen)
{
    mbedtls_asn1_buf  params;
    rnginfo_t        *rng; 
    uint8_t          *p = (uint8_t *) key;
    uint8_t          *end = p + klen;
    uint8_t          *end2;
    size_t            len;
    int               version, pubkey_done;
    int               rc = LIB_ERROR;
    
        
    /*---------------------Code ----------------------------------------------*/
    /*
     * RFC 5915, or SEC1 Appendix C.4
     *
     * ECPrivateKey ::= SEQUENCE {
     *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey     OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey  [1] BIT STRING OPTIONAL
     *    }
     */
    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != SUCCESS )
        goto fail_invalid_format;

    end = p + len; 
    SET_VAL_SAFE( der_olen, (size_t)(p - key) + len);  // Set the size of the DER key 

    if( ( rc = mbedtls_asn1_get_int( &p, end, &version ) ) != SUCCESS)
        goto fail_invalid_format;

    if( version != 1 )
        goto fail_invalid_version; 

    if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != SUCCESS )
        goto fail_invalid_format;

    if( ( rc = mbedtls_mpi_read_binary( &eckey->d, p, len ) ) != SUCCESS )
        goto fail_invalid_format;

    p += len;

    pubkey_done = 0;
    if( p != end )
    {
        /*
         * Is 'parameters' present?
         */
        if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) == 0 )
        {
            if( ( rc = get_ecparams( &p, p + len, &params) ) != SUCCESS ||
                ( rc = use_ecparams( &params, &eckey->grp )  ) != SUCCESS )
            {
                goto fail; 
            }
        }
        else if( rc != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            goto fail_invalid_format;
    }

    if( p != end )
    {
        /*
         * Is 'publickey' present? If not, or if we can't read it (eg because it
         * is compressed), create it from the private key.
         */
        if( ( rc = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) ) == 0 )
        {
            end2 = p + len;

            if( ( rc = mbedtls_asn1_get_bitstring_null( &p, end2, &len ) ) != SUCCESS )
                goto fail_invalid_format;

            if( p + len != end2 ) {
                rc = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH; 
                goto fail_invalid_format;
            }

            if( ( rc = get_ecpubkey( &p, end2, eckey ) ) == 0 )
                pubkey_done = 1;
            else
            {
                /*
                 * The only acceptable failure mode of get_ecpubkey() above
                 * is if the point format is not recognized.
                 */
                if( rc != MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE )
                    return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
            }
        }
        else if( rc != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            goto fail_invalid_format;
    }

    if( pubkey_done == FALSE) 
    {
        if(( rc= pkey_get_rng_info((pktop_t *)eckey->pktop, &rng )) != SUCCESS)
            goto fail;  

        if ((rc = mbedtls_ecp_mul(&eckey->grp, &eckey->Q, &eckey->d, &eckey->grp.G, rng->cb, rng->ctx)) != SUCCESS)
            goto fail_invalid_format;
    }

    if( ( rc = mbedtls_ecp_check_privkey( &eckey->grp, &eckey->d ) ) != 0 )
        goto fail_invalid_format;
    return SUCCESS;


     // --- Error handling --- 
fail_invalid_version:
    rc = MBEDTLS_ERR_PK_KEY_INVALID_VERSION; goto fail; 
fail_invalid_format: 
    rc = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, rc); 
fail: 
    mbedtls_ecp_keypair_free( eckey ); //cleanup 
    SET_VAL_SAFE( der_olen, 0);  // Set the size of the DER key 
    return rc;       
}


/* ---------------------------------------------------------------------------
  * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 * ---------------------------------------------------------------------------*/
static int write_ec_param( eckey_t *eckey, uint8_t **p, uint8_t *start)
{
    const char *oid;
    size_t      len = 0;
    size_t      oid_len;
    int         rc = LIB_ERROR;

    if (eckey->grp.id == MBEDTLS_ECP_DP_CURVE25519)
        LOGW("%s(): X25519 curve is USING a fake OID\n", __func__); 

    if ((rc = mbedtls_oid_get_oid_by_ec_grp( eckey->grp.id, &oid, &oid_len )) != 0)
        goto fail;
    ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid, oid_len ) );

    return( (int) len );

    // --- Error handling ---
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}


/* ---------------------------------------------------------------------------
 * privateKey  OCTET STRING -- always of length ceil(log2(n)/8)
 * ---------------------------------------------------------------------------*/
static int write_ec_private( eckey_t *eckey, uint8_t **p, uint8_t *start)
{
    uint8_t  tmp[MBEDTLS_ECP_MAX_BYTES];
    int      rc = LIB_ERROR;
    size_t   byte_length = ( eckey->grp.pbits + 7 ) / 8;

    /*---------------------Code ----------------------------------------------*/
    rc = mbedtls_ecp_write_key( eckey, tmp, byte_length );
    if( rc != 0 )
        goto fail;
    rc = mbedtls_asn1_write_octet_string( p, start, tmp, byte_length );

    // --- Error handling ---
fail:
    mbedtls_platform_zeroize( tmp, byte_length );
    return( rc );
}


/* ---------------------------------------------------------------------------
 * EC public key is an EC point  
 * ---------------------------------------------------------------------------*/
static int write_ec_pubkey( eckey_t *eckey, uint8_t **p, uint8_t *start)
{
    int rc = LIB_ERROR;
    size_t len = 0;
    uint8_t buf[MBEDTLS_ECP_MAX_PT_LEN];

    if( ( rc = mbedtls_ecp_point_write_binary( &eckey->grp, &eckey->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                &len, buf, sizeof( buf ) ) ) != 0 )
    {
        return( rc );
    }

    if( *p < start || (size_t)( *p - start ) < len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *p -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}


/* ---------------------------------------------------------------------------
 * Export the EC key in PKCS8 DER format   
 * ---------------------------------------------------------------------------*/
int eckey_export_der_pkcs8( eckey_t *eckey,  pkbuf_t *odata)
{
    uint8_t     *c;      // active pointer in the buffer 
    uint8_t     *start;  // Start of the buffer 
    size_t       osize, len = 0, par_len=0, pub_len = 0;
    int          rc;
    const char  *oid;
    size_t       oid_len;
    int          version;

    /*---------------------Code ----------------------------------------------*/
    /*
     * RFC 5915, or SEC1 Appendix C.4
     *
     * ECPrivateKey ::= SEQUENCE {
     *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey     OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey  [1] BIT STRING OPTIONAL
     *    }
     */
    pkbuf_extract(odata, &start, &osize, &len); 
    c = start + osize; 

    /* publicKey */
    ASN1_CHK_ADD(pub_len, write_ec_pubkey(eckey, &c, start));
    if (c - start < 1)
        goto fail_buffer_size;
    *--c = 0;
    pub_len += 1;

    ASN1_CHK_ADD(pub_len, mbedtls_asn1_write_len(&c, start, pub_len));
    ASN1_CHK_ADD(pub_len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_BIT_STRING));

    ASN1_CHK_ADD(pub_len, mbedtls_asn1_write_len(&c, start, pub_len));
    ASN1_CHK_ADD(pub_len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1));
    len += pub_len;

    /* privateKey */
    ASN1_CHK_ADD(len, write_ec_private(eckey, &c, start));

    /* version */
    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, start, 1));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /*   ADD PKCS8 PrivateKeyAlgorithmIdentifier
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
    */
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_OCTET_STRING));

    /* Add EC parameters OID */
    par_len = 0;
    ASN1_CHK_ADD(par_len, write_ec_param(eckey, &c, start));

    // Write Private octet string len and tag 

    // Write PK algorithm OID: Use the hardcoded oid data 
    oid     = (const char*)ec_oid.buf;
    oid_len = ec_oid.size;
    ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, start, oid, oid_len, par_len));

    // Write version 
    version = 0; 
    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, start, version));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    odata->iolen = len; 
    return SUCCESS; 

    // --- Error handling ---
fail_buffer_size: 
    rc = MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
fail: 
    LOGD( "%s() FAILED with rc=-0x%x\n", __func__, -rc );
    mbedtls_platform_zeroize( (void*)odata->buf, odata->size);
    odata->iolen = 0; 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * Export the EC pubkey key in DER format   
 * ---------------------------------------------------------------------------*/
int eckey_export_pubkey_der( eckey_t *eckey,  pkbuf_t *odata)
{
    uint8_t     *p;      // active pointer in the buffer 
    uint8_t     *start;  // Start of the buffer 
    const char  *oid;
    size_t       len = 0, par_len = 0, oid_len;
    int          rc;

    /*---------------------Code ----------------------------------------------*/
    start = (uint8_t*)odata->buf; 
    p = start + odata->size;   // Start at the emd of the buffer and write backwards 

    ASN1_CHK_ADD(len, write_ec_pubkey(eckey, &p, start));
    if (p - start < 1)
        goto fail_bufsize; 

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--p = 0;
    len += 1;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_BIT_STRING));

    ASN1_CHK_ADD(par_len, write_ec_param(eckey, &p, start));

    // Write PK algorithm OID: Use the hardcoded oid data 
    oid     = (const char*)ec_oid.buf;
    oid_len = ec_oid.size;    
    ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&p, start, oid, oid_len, par_len));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    odata->iolen = len; 

    return SUCCESS; 

    // --- Error handling ---
fail_bufsize:
    rc = MBEDTLS_ERR_ASN1_BUF_TOO_SMALL; 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    mbedtls_platform_zeroize((void*)odata->buf, odata->size);
    odata->iolen = 0; 
    return rc; 
}


/* ---------------------------------------------------------------------------
 * Export the EC pubkey key in DER format   
 * ---------------------------------------------------------------------------*/
int eckey_export_pubkey_ssl( eckey_t *eckey,  pktarget_e target, pkbuf_t *odata)
{
    uint8_t     *p;      // active pointer in the buffer 
    uint8_t     *start;  // Start of the buffer 
    size_t       publen;
    int          rc;

    /*---------------------Code ----------------------------------------------*/
    start = (uint8_t*)odata->buf; 
    p     = start + odata->size; 
    publen  = 0;
    ASN1_CHK_ADD(publen, write_ec_pubkey(eckey, &p, start));
    if (p - start < 1)
        goto fail_bufsize; 
    
    *(--p) = (uint8_t)publen;    // Last byte of the header is the size of the public key 

    // --- An SSL KEM, DH response pubkey only prefixes the pubkey length. 
    // --- So add the group information ONLY for the initiating DH public key exchange  
    if ( target == PK_TARGET_PUBSSL)
    
    {
        uint8_t      buf[10]; 
        size_t       grplen;

        if( (rc = mbedtls_ecp_tls_write_group( &eckey->grp, &grplen, buf, sizeof(buf))) != 0) 
            goto fail; 
        p -= grplen; 
        memcpy(p , buf, grplen);
    }
    odata->iolen = start + odata->size - p; 
    return 0;  

fail_bufsize:
    rc = MBEDTLS_ERR_ASN1_BUF_TOO_SMALL; 
fail: 
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    odata->iolen = 0; 
    return rc; 
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
static int eckey_export_key_text(eckey_t *eckey, pktarget_e target, pkexport_e level, pkbuf_t *result)
{
    pkbuf_t      odata;  // Make a working copy that can be modified
    uint8_t      qbuf[256], *p;  
    const char  *curve_name;
    size_t       olen, len, bitlen = 0;
    int          rc, dump_full = 0; 
    (void) level; 

    /*---------------------Code ----------------------------------------------*/
    pkbuf_init( &odata, result->buf, result->size, result->iolen); 
    *(uint8_t*)(odata.buf + odata.size - 1) = 0;              // Null terminate, just in case

    bitlen = eckey->grp.pbits;

    if (target == PK_TARGET_PRV)
        olen = snprintf( (char *)odata.buf, odata.size, "EC Private-Key: (%d bit)\n", (int)bitlen );
    else
        olen = snprintf( (char *)odata.buf, odata.size, "EC Public-Key:\n");
    pkbuf_move(&odata, olen);

    if (target == PK_TARGET_PRV)
        util_write_mpi_formatted( &eckey->d, 0, &odata, "priv" );

    // write the public key
    p = qbuf + sizeof(qbuf); 
    if( (rc = write_ec_pubkey(eckey, &p, qbuf)) < 0) 
        goto fail; 
    len = (size_t)((qbuf + sizeof(qbuf)) - p);

    if ( level == PK_EXPORT_FULL)
        dump_full = TRUE;
  #ifdef OPENSSL_FORMATTED_DUMP
    olen = util_dump2buf(p, len, ':', 15, &odata, "pub", dump_full);
  #else 
    olen = util_dump2buf(p, len, ' ', 32, &odata, "pub", dump_full);
  #endif 
    pkbuf_move( &odata, olen);
    curve_name = mbedtls_ecp_curve_info_from_grp_id( eckey->grp.id )->name; 
    olen = snprintf( (char *)odata.buf, odata.size, "curve: %s\n\n", curve_name);
    pkbuf_move( &odata, olen); 

    // Update the length of the data written
    result->iolen = result->size - odata.size;
    return result->iolen;

    // --- Error handling ---
fail:  
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc;
}

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- EC wrapper Functions -------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
/******************************************************************************
  * Description: get the key paramater info 
  *
  * Arguments:   pkctx    - EC key context 
  *
  * result:      pointer to the key paramaters structure 
  *****************************************************************************/
static pk_keyparams_t *eckey_get_keyparams_wrap( void *pkctx)  
{   
    eckey_t               *eckey = (eckey_t*)pkctx;                                       
    size_t                 publen;
    struct pk_keyparams_s *kparms = (struct pk_keyparams_s *)eckey->key_params;

    if (kparms->initialized == 0 )
    {
        if( (publen = ((eckey->grp.pbits+7)/8)) != 0) 
        {
            kparms->pk_len  = publen; 
            kparms->sk_len  = (eckey->grp.nbits+7)/8; 
            kparms->sig_len = publen; 
            kparms->ss_len  = kparms->sk_len; 
            kparms->name    = "EC"; 
            memcpy( &kparms->oid, &ec_oid, sizeof(pkbuf_t)); 
            kparms->initialized = 1; 
        }
    }
    return kparms;
}



/* ---------------------------------------------------------------------------
 * EC get bitlen wrapper  
 * ---------------------------------------------------------------------------*/
//static int eckey_get_bitlen( void *pkctx, size_t *bitlen)
//{
 //   *bitlen = ((eckey_t *)pkctx)->grp.pbits;
 //   return SUCCESS;
//}

#if defined(MBEDTLS_ECDSA_C)
/* ---------------------------------------------------------------------------
 * EC key verify signature wrapper 
 * ---------------------------------------------------------------------------*/
static int eckey_vrfy_wrap(void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig, void *rs_ctx)
{
    eckey_t               *eckey = (eckey_t *)pkctx;
    mbedtls_ecdsa_context  ecdsa;
    int                    rc;
    (void) md_alg;
    (void) rs_ctx;


    /*---------------------Code ----------------------------------------------*/
    mbedtls_ecdsa_init(&ecdsa);

    if ((rc = mbedtls_ecdsa_from_keypair(&ecdsa, eckey)) != SUCCESS)
        goto fail;

    if ((rc = mbedtls_ecdsa_read_signature(&ecdsa, hash->buf, hash->size, sig->buf, sig->size, &sig->iolen)) != SUCCESS)
        goto fail;
    goto cleanup;  // SUCCESS 

    // --- Error handling ---
fail:  
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    sig->iolen = 0;
cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    return rc;
}


/* ---------------------------------------------------------------------------
 * EC key create ignature wrapper 
 * ---------------------------------------------------------------------------*/
static int eckey_sign_wrap( void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig_out, void *rs_ctx) 
{
    eckey_t               *eckey = (eckey_t *)pkctx;
    rnginfo_t             *rng;
    mbedtls_ecdsa_context  ecdsa;
    int                    rc; 
    (void) rs_ctx;

    /*---------------------Code ----------------------------------------------*/
    mbedtls_ecdsa_init( &ecdsa );

    if( ( rc = mbedtls_ecdsa_from_keypair( &ecdsa, eckey) ) != SUCCESS )
        goto fail;

    if((rc = pkey_get_rng_info((pktop_t *)eckey->pktop, &rng )) != SUCCESS)
        goto fail;  

    rc = mbedtls_ecdsa_write_signature(&ecdsa, md_alg, hash->buf, hash->size, (uint8_t*)sig_out->buf, sig_out->size, 
                                       &sig_out->iolen, rng->cb, rng->ctx); 
    if (rc != SUCCESS)
        goto fail;
    goto cleanup;

    // --- Error handling --- 
fail:  
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
cleanup:
    mbedtls_ecdsa_free( &ecdsa );
    return rc;
}
#else 
#define eckey_vrfy_wrap  NULL 
#define eckey_sign_wrap  NULL 
#endif /* MBEDTLS_ECDSA_C */


#if defined(MBEDTLS_ECDH_C) 
/* ---------------------------------------------------------------------------
 * EC key create shared secret (ss) 
 * ---------------------------------------------------------------------------*/
static int eckey_dh_wrap( void *pkctx, void *peer, pkbuf_t *shared) 
{
    eckey_t                   *eckey      = (eckey_t *)pkctx;
    eckey_t                   *eckey_peer = (eckey_t *)peer;
    rnginfo_t                 *rng;
    mbedtls_ecdh_context       ecdh;
    mbedtls_ecdh_context_mbed *ecdh_mbed; 
    int                        rc; 


    /*---------------------Code ----------------------------------------------*/
    mbedtls_ecdh_init( &ecdh );
    ecdh_mbed = &ecdh.ctx.mbed_ecdh; 

    if( eckey->grp.id != eckey_peer->grp.id) 
        goto fail_mismatch; 

    if(( rc = mbedtls_ecdh_setup( &ecdh, eckey->grp.id)) != SUCCESS)
        goto fail; 

    // Copy the private key to ecdh context 
    if((rc = mbedtls_ecp_group_load( &ecdh_mbed->grp, eckey->grp.id)) != SUCCESS)
        goto fail;
    if((rc = mbedtls_mpi_copy( &ecdh_mbed->d,  &eckey->d)) != SUCCESS)
        goto fail;
    if((rc = mbedtls_ecp_copy( &ecdh_mbed->Q,  &eckey->Q)) != SUCCESS)
        goto fail;
    
    // Copy the peer public key to ecdh context 
    if((rc = mbedtls_ecp_copy( &ecdh_mbed->Qp, &eckey_peer->Q)) != SUCCESS)
        goto fail;
  
    if((rc = pkey_get_rng_info((pktop_t *)eckey->pktop, &rng )) != SUCCESS)
            goto fail;  


    // Calculate the shared secret 
    if(( rc = mbedtls_ecdh_calc_secret(&ecdh, &shared->iolen, (uint8_t*)shared->buf, shared->size, rng->cb, rng->ctx)) != SUCCESS) 
        goto fail;
    rc = SUCCESS;
    goto cleanup; 

    // --- Error handling --- 
fail_mismatch:  
    rc = MBEDTLS_ERR_ECP_TYPE_MISMATCH;
fail:  
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
cleanup:
    mbedtls_ecdh_free( &ecdh );
    return rc;
}
#else
#define eckey_dh_wrap  NULL 
#endif  // #if defined(MBEDTLS_ECDH_C) 

/* ---------------------------------------------------------------------------
 * EC keygen wrapper 
 * ---------------------------------------------------------------------------*/
static int eckey_keygen_wrap(void *pkctx, char* keygen_params)
{
    eckey_t                       *eckey = (eckey_t*)pkctx;
    mbedtls_ecp_group_id           grp_id; 
    const mbedtls_ecp_curve_info  *curve_info;
    rnginfo_t                     *rng; 
    char                          *rest, *token;
    const char                    *curve = NULL; 
    int                            rc; 


    /*---------------------Code ----------------------------------------------*/
    // parse the keygen_params
    rest  = keygen_params;
    curve = "secp256r1"; 
    LOGD("%s() keygen_params=%s\n", __func__, keygen_params);
    while ((token = strtok_r( rest, ":", &rest )))
    {
        // LOGD( "%s\n", token );
        if (strncmp( token, "curve=", 6 ) == 0)
            curve = token + 6;
        else 
            goto fail_bad_input;
    }
    if (curve == NULL)
        goto fail_bad_input;

    if ((curve_info = (const mbedtls_ecp_curve_info *)mbedtls_ecp_curve_info_from_name( curve )) == NULL)
        goto fail_bad_input;

    grp_id = curve_info->MBEDTLS_PRIVATE(grp_id);

    if ((rc = pkey_get_rng_info( (pktop_t *)eckey->pktop, &rng )) != SUCCESS)
        goto fail;
    
    // LOGD("%s(): grp_id=%d\n", __func__, (int)grp_id);
    if ((rc = mbedtls_ecp_gen_key( grp_id, eckey, rng->cb, rng->ctx )) != SUCCESS)
        goto fail;
    return SUCCESS; 


    // --- Error handling --- 
fail_bad_input: 
    rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
fail: 
    return rc;
}


/* ---------------------------------------------------------------------------
 * EC key check public/private key match 
 * ---------------------------------------------------------------------------*/
static int eckey_check_pair_wrap( void *pkctx_pub, void *pkctx_prv)
{
    const eckey_t  *eckey_pub = (eckey_t *)pkctx_pub;
    const eckey_t  *eckey_prv = (eckey_t *)pkctx_prv;
    rnginfo_t      *rng;
    int             rc; 

    /*---------------------Code ----------------------------------------------*/
    if ((rc = pkey_get_rng_info( (pktop_t *)eckey_prv->pktop, &rng )) != SUCCESS)
        goto fail;

    if ((rc = mbedtls_ecp_check_pub_priv( eckey_pub, eckey_prv, rng->cb, rng->ctx )) != SUCCESS)
        goto fail;
    return SUCCESS;

    // --- Error handling --- 
fail:  
    return rc;
}


/* ---------------------------------------------------------------------------
 * EC key alloc key context function  
 * ---------------------------------------------------------------------------*/
static void* eckey_alloc_wrap(pkfull_t *pkfull)
{
    eckey_t *eckey = (eckey_t *)mbedtls_calloc(1, sizeof(eckey_t));

    if (eckey != NULL) 
    {
        mbedtls_ecp_keypair_init(eckey);
        eckey->key_params = mbed_calloc( 1, sizeof(pk_keyparams_t)); 
        eckey->pktop  = (void *)pkfull->pktop;  // Reference back to the top level
    }
    return  (void *)eckey;
}


/* ---------------------------------------------------------------------------
 * EC key free key context function  
 * ---------------------------------------------------------------------------*/
static void *eckey_free_wrap( void *pkctx )
{
    eckey_t *eckey = (eckey_t*)pkctx; 

    mbedtls_ecp_keypair_free(eckey);
    eckey->key_params = mbed_free( eckey->key_params);
    mbed_free( pkctx );
    return NULL;
}

/* ---------------------------------------------------------------------------
 * Wrapper import EC key in DER format 
 * ---------------------------------------------------------------------------*/
static int eckey_import_wrap( void *pkctx, pktarget_e target, pkbuf_t *idata, void *alg_info, size_t *der_olen) 
{
   eckey_t           *eckey = (eckey_t*)pkctx; 
   uint8_t           *p; 
   int                rc = 0;


   /*---------------------Code ----------------------------------------------*/
   if (( target == PK_TARGET_PUBSSL) || ( target == PK_TARGET_PUBSSL_RESP)) 
   {
       mbedtls_ecp_group_id  grp_id;
       size_t                hdr_len; 
       int                   publen;

       p = (uint8_t*)idata->buf; 
       if ( target == PK_TARGET_PUBSSL_RESP )
       {
           // The opaque algo_info variable contains a pointer to a prototype eckey 
           grp_id = ((eckey_t*)alg_info)->grp.id; 
       }
       else // PK_TARGET_PUBSSL 
       {
           // Read the curve group information 
           if ((rc = mbedtls_ecp_tls_read_group_id( &grp_id, (const uint8_t **)&p, idata->size )) != 0)
               goto fail;
       }
       publen = *p++;  // Get the public key length 
       if( ( rc = mbedtls_ecp_group_load( &eckey->grp, grp_id ) ) != 0 )
           goto fail;
       hdr_len = p - idata->buf; 
       if (hdr_len + publen > idata->size) 
       {
           rc = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL; 
           goto fail; 
       }
       SET_VAL_SAFE( der_olen, hdr_len + publen );
       rc = get_ecpubkey( &p, p+publen, eckey); 
   }
   else 
   {
       asn1buf_t *alg_params = (asn1buf_t *)alg_info;
       if (alg_params != NULL)
           rc = use_ecparams(alg_params, &eckey->grp); // Check if the eckey grp is setup correctly

       if (target == PK_TARGET_PRV)
           rc = parse_key_sec1_der(eckey, idata->buf, idata->size, der_olen);
       else if (target == PK_TARGET_PUB)
       {
           p = (uint8_t*)idata->buf; 
           rc = get_ecpubkey( &p, p+idata->size, eckey); 
           SET_VAL_SAFE(der_olen, (size_t)(p - idata->buf)); 
       }
       else 
           rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
   }
   if (rc != SUCCESS)
       goto fail;   
   return rc;
    
    // --- Error handling --- 
fail:
    LOGD("%s() FAILED with rc=-0x%x\n", __func__, -rc); 
    return rc; 
}

/* ---------------------------------------------------------------------------
 * Wrapper export EC key 
 * export format: 0 is DER, 1=BASIC, 2=EXTENDED, 3=FULL 
 * return:  Minimum size of buffer required or buf  
 * ---------------------------------------------------------------------------*/
static int eckey_export_wrap( void *pkctx, pktarget_e target, pkexport_e level, pkbuf_t *result) 
{
    eckey_t  *eckey = (eckey_t*)pkctx; 
    int       rc; 

    /*---------------------Code ----------------------------------------------*/
    if ( level == PK_EXPORT_DER)
    {
        if (target == PK_TARGET_PRV)
            rc = eckey_export_der_pkcs8(eckey, result);
        else if (target == PK_TARGET_PUB)
            rc = eckey_export_pubkey_der(eckey, result);
        else if ((target == PK_TARGET_PUBSSL) || (target == PK_TARGET_PUBSSL_RESP)) 
             rc = eckey_export_pubkey_ssl(eckey, target, result);
        else 
            rc = MBEDTLS_ERR_PK_BAD_INPUT_DATA; 
    }
    else 
    {
        rc = eckey_export_key_text( eckey, target, level, result );
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
static void eckey_debug_wrap( void *ctx, mbedtls_pk_debug_item *items )
{
    items->type = MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((mbedtls_ecp_keypair *) ctx)->Q );
}

//----------------------------------------------------------------------------
//----------------- Constants ------------------------------------------------
//----------------------------------------------------------------------------
pkinfo_t eckey_pkinfo = {
    MBEDTLS_PK_ECKEY,
    eckey_get_keyparams_wrap,
    eckey_vrfy_wrap,
    eckey_sign_wrap,             
    NULL,                         // decapsulate not supported  
    NULL,                         // encapsulate not supported  
    eckey_dh_wrap,    
    eckey_keygen_wrap,
    eckey_check_pair_wrap,
    eckey_alloc_wrap,       
    eckey_free_wrap,        
    eckey_import_wrap,
    eckey_export_wrap,
    eckey_debug_wrap
};

pkinfo_t ecdh_pkinfo = {
    MBEDTLS_PK_ECKEY_DH,
    eckey_get_keyparams_wrap,
    NULL,                         // verify not supported 
    NULL,                         // sign not supported 
    NULL,                         // decapsulate not supported  
    NULL,                         // encapsulate not supported  
    eckey_dh_wrap,    
    eckey_keygen_wrap,
    eckey_check_pair_wrap,
    eckey_alloc_wrap,       
    eckey_free_wrap,        
    eckey_import_wrap,
    eckey_export_wrap,
    eckey_debug_wrap
};

#if defined(MBEDTLS_ECDSA_C)
pkinfo_t ecdsa_pkinfo = {
    MBEDTLS_PK_ECDSA,
    //&ec_oid,                 
    //"EC",
    eckey_get_keyparams_wrap,
    eckey_vrfy_wrap,
    eckey_sign_wrap,             
    NULL,                         // decapsulate not supported  
    NULL,                         // encapsulate not supported  
    NULL,                         // diffie hellman not supported     
    eckey_keygen_wrap,
    eckey_check_pair_wrap,
    eckey_alloc_wrap,       
    eckey_free_wrap,        
    eckey_import_wrap,
    eckey_export_wrap,
    eckey_debug_wrap
};
#endif 

/*----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------- API Functions --------------------------------------------*
 *----------------------------------------------------------------------------*
 *----------------------------------------------------------------------------*/
#if 0 
/* ---------------------------------------------------------------------------
 *  Get pkinfo structure from type 
 * ---------------------------------------------------------------------------*/
pkinfo_t *pkey_ec_get_pkinfo( pktype_e pktype)
{
    switch( pktype ) {
        case MBEDTLS_PK_ECKEY:
            return( &eckey_pkinfo );
        case MBEDTLS_PK_ECKEY_DH:
            return( &ecdh_pkinfo );
      #if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_PK_ECDSA:
            return( &ecdsa_pkinfo );
      #endif
        default:
            return( NULL );
    }
}
#endif 
/* ---------------------------------------------------------------------------
 *  Register the algorithm as a constructor
 *  * ---------------------------------------------------------------------------*/
int pkey_eckey_enable_constructors;  /* not used for anything except for the linker to link the constructor */

void __attribute__ ((used, constructor)) pkey_eckey_constructor(void)
{
    pkey_register_pk_algorithm(&eckey_pkinfo); 
    pkey_register_pk_algorithm(&ecdh_pkinfo); 
  #if defined(MBEDTLS_ECDSA_C)
    pkey_register_pk_algorithm(&ecdsa_pkinfo); 
  #endif
}

#endif /* MBEDTLS_ECP_C */ 
#endif /* MBEDTLS_PK_C */
