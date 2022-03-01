/**
 * \file pk.h
 *
 * \brief Public Key (pk) abstraction layer with Post Quantum 
 *        (pq) support. 
 */
/*
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

#ifndef MBEDTLS_PKPQ_H
#define MBEDTLS_PKPQ_H


//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <stdint.h>

#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/md.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif      // from: #if defined(MBEDTLS_RSA_C)

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif      // from: #if defined(MBEDTLS_ECP_C)

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif     // from: #if defined(MBEDTLS_ECDSA_C)

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif    // #if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && !defined(inline) && !defined(__cplusplus)

//----------------------------------------------------------------------------
//----------------- Erorr Defines --------------------------------------------
//----------------------------------------------------------------------------

#define MBEDTLS_ERR_PK_ALLOC_FAILED        -0x3F80  /**< Memory allocation failed. */
#define MBEDTLS_ERR_PK_TYPE_MISMATCH       -0x3F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA      -0x3E80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_PK_FILE_IO_ERROR       -0x3E00  /**< Read/write of file failed. */
#define MBEDTLS_ERR_PK_KEY_INVALID_VERSION -0x3D80  /**< Unsupported key version */
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00  /**< Invalid key tag or value. */
#define MBEDTLS_ERR_PK_UNKNOWN_PK_ALG      -0x3C80  /**< Key algorithm is unsupported (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_PASSWORD_REQUIRED   -0x3C00  /**< Private key password can't be empty. */
#define MBEDTLS_ERR_PK_PASSWORD_MISMATCH   -0x3B80  /**< Given private key password does not allow for correct decryption. */
#define MBEDTLS_ERR_PK_INVALID_PUBKEY      -0x3B00  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_INVALID_ALG         -0x3A80  /**< The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00  /**< Elliptic curve is unsupported (only NIST curves are supported). */
#define MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE -0x3980  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
#define MBEDTLS_ERR_PK_SIG_LEN_MISMATCH    -0x3900  /**< The buffer contains a valid signature followed by more data. */
#define MBEDTLS_ERR_PK_BUFFER_TOO_SMALL    -0x3880  /**< The output buffer is too small. */
#define MBEDTLS_ERR_PK_INCOMPATIBLE_ALGO   -0x3800  /**< Try to add an incompatible algortihm to the top key  */
#define MBEDTLS_ERR_PK_INTERNAL_ERROR      -0x3780  /**< Incorrect code implementation  */
#define MBEDTLS_ERR_PK_DECAP_ERROR         -0x3700  /**< Secret key decapsulation error */
#define MBEDTLS_ERR_PK_ENCAP_ERROR         -0x3680  /**< Public key encapsulation error */
#define MBEDTLS_ERR_PK_NUM_KEYS_ERROR      -0x3600  /**< Number of keys in the hybrid key error */

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define  MBED_PRIV  MBEDTLS_PRIVATE

/**
 * \brief           Maximum size of a signature made by mbed_pk_sign().
 */
/* We need to set MBEDTLS_PK_SIGNATURE_MAX_SIZE to the maximum signature
 * size among the supported signature types. Do it by starting at 0,
 * then incrementally increasing to be large enough for each supported
 * signature mechanism.
 *
 * The resulting value can be 0, for example if MBEDTLS_ECDH_C is enabled
 * (which allows the pk module to be included) but neither MBEDTLS_ECDSA_C
 * nor MBEDTLS_RSA_C nor any opaque signature mechanism (PSA or RSA_ALT).
 */
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE 0
#if defined(MBEDTLS_PQ_C) && (MBEDTLS_PK_SIGNATURE_MAX_SIZE < 10000)
  #undef MBEDTLS_PK_SIGNATURE_MAX_SIZE
  #define MBEDTLS_PK_SIGNATURE_MAX_SIZE 10000
  #define MBEDTLS_PK_HYBKEY_MAX_SIZE    20000
#endif 

#if ( defined(MBEDTLS_RSA_C) || defined(MBEDTLS_PK_RSA_ALT_SUPPORT) ) && MBEDTLS_MPI_MAX_SIZE > MBEDTLS_PK_SIGNATURE_MAX_SIZE
  /* For RSA, the signature can be as large as the bignum module allows.
   * For RSA_ALT, the signature size is not necessarily tied to what the
   * bignum module can do, but in the absence of any specific setting,
   * we use that (rsa_alt_sign_wrap in library/pk_wrap.h will check). */
  #undef MBEDTLS_PK_SIGNATURE_MAX_SIZE
  #define MBEDTLS_PK_SIGNATURE_MAX_SIZE MBEDTLS_MPI_MAX_SIZE
#endif    // from:  #if ( defined(MBEDTLS_RSA_C) || defined(MBEDTLS_PK_RSA_ALT_SUPPORT) ) && MBEDTLS_MPI_MAX_SIZE > MBEDTLS_PK_SIGNATURE_MAX_SIZE


#if defined(MBEDTLS_ECDSA_C) && MBEDTLS_ECDSA_MAX_LEN > MBEDTLS_PK_SIGNATURE_MAX_SIZE
  /* For ECDSA, the ecdsa module exports a constant for the maximum
   * signature size. */
  #undef MBEDTLS_PK_SIGNATURE_MAX_SIZE
  #define MBEDTLS_PK_SIGNATURE_MAX_SIZE MBEDTLS_ECDSA_MAX_LEN
#endif   // from: #if defined(MBEDTLS_ECDSA_C) && MBEDTLS_ECDSA_MAX_LEN > MBEDTLS_PK_SIGNATURE_MAX_SIZE

//----------------------------------------------------------------------------
//----------------- Enums and typedefs ---------------------------------------
//----------------------------------------------------------------------------

typedef unsigned char mbed_pktop_t;   // External reference to top public key context   


/**
 * \brief           Random number generator callback fucntion define 
 */
typedef int (*mbed_rng_cb_t)(void *, uint8_t *, size_t);
typedef int (*mbed_entropy_cb_t)(void *, uint8_t *, size_t);

typedef uint64_t mbed_hybpk_t;     // Combined type of all (sub)keys in a top level key.

/**
 * \brief          Public key algortihm types
 */
typedef enum {
    MBEDTLS_PK_NONE=0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_OPAQUE,
 #ifdef MBEDTLS_PQ_C
    MBEDTLS_PK_DILITHIUM,
    MBEDTLS_PK_KYBER,
    MBEDTLS_PK_DH,               
    MBEDTLS_PK_MULTI,            // Virtual: Only used to add a MULTI key OID to the public key 
 #endif 
    MBEDTLS_PK_LAST              // WARNING: values cannot exceed 255 ( per PKEY_COMB_TYPE_SHIFT)  
} mbed_pktype_e;

#ifdef MBEDTLS_PQ_C
    #define MBEDTLS_PK_HYBDSA    ((MBEDTLS_PK_DILITHIUM<<8) +  MBEDTLS_PK_ECKEY)   
    #define MBEDTLS_PK_HYBKEM    ((MBEDTLS_PK_KYBER<<8)     +  MBEDTLS_PK_ECKEY_DH)   
    // #define MBEDTLS_PK_HYBKEM     (MBEDTLS_PK_ECKEY_DH)   
    #define MBEDTLS_PK_PQDSA     (MBEDTLS_PK_DILITHIUM)   
    #define MBEDTLS_PK_PQKEM     (MBEDTLS_PK_KYBER)   
#endif 

/**
 * \brief          Export types 
 */
typedef enum    
{
    PK_EXPORT_DER,         // DER export format 
    PK_EXPORT_BASIC,       // Basic text 
    PK_EXPORT_EXTENDED,    // Extended text 
    PK_EXPORT_FULL,        // Full text
    PK_EXPORT_LAST         // Last entry
} mbed_pkexport_e;


typedef enum 
{
    PK_TARGET_PRV         = 0, 
    PK_TARGET_PUB         = 1, 
    PK_TARGET_PUBSSL      = 2, 
    PK_TARGET_PUBSSL_RESP = 3
} mbed_pktarget_e; 

typedef enum
{
    MBED_NIST_LEVEL_NONE = 0, 
    MBED_NIST_LEVEL_1    = 1, 
    MBED_NIST_LEVEL_2    = 2, 
    MBED_NIST_LEVEL_3    = 3, 
    MBED_NIST_LEVEL_4    = 4, 
    MBED_NIST_LEVEL_5    = 5
} mbed_nistlevel_e;          // NIST security levels 


/**
 * \brief          message en/decapsulation mode 
 */
typedef enum {
    MBED_CAPMODE_NONE=0,
    MBED_CAPMODE_RAW,
    MBED_CAPMODE_PKCS1_5,
    MBED_CAPMODE_OEAP
} mbed_capmode_e;

typedef void  mbedtls_pk_restart_ctx;


/**
 * \brief           Options for RSASSA-PSS signature verification.
 *                  See \c mbedtls_rsa_rsassa_pss_verify_ext()
 */
typedef struct mbedtls_pk_rsassa_pss_options
{
    mbed_md_alg_e  MBED_PRIV(mgf1_hash_id);
    int            MBED_PRIV(expected_salt_len);

} mbedtls_pk_rsassa_pss_options;



/**
 * \brief           Types for interfacing with the debug module
 */
typedef enum
{
    MBEDTLS_PK_DEBUG_NONE = 0,
    MBEDTLS_PK_DEBUG_MPI,
    MBEDTLS_PK_DEBUG_ECP,
    MBEDTLS_PK_DEBUG_DILITH,
} mbedtls_pk_debug_type;



/**
 * \brief           Item to send to the debug module
 */
typedef struct mbedtls_pk_debug_item
{
    mbedtls_pk_debug_type  MBED_PRIV(type);
    const char            *MBED_PRIV(name);
    void                  *MBED_PRIV(value);
} mbedtls_pk_debug_item;



/** Maximum number of item send for debugging, plus 1 */
#define MBEDTLS_PK_DEBUG_MAX_ITEMS 3


//----------------------------------------------------------------------------
//----------------- Function prototypes --------------------------------------
//----------------------------------------------------------------------------
int mbed_pk_get_rnginfo( mbed_pktop_t *pktop_prv_ref, mbed_rng_cb_t *f_rng, void **p_rng);

/**
 * \brief           Initialize a #pktop (as NONE).
 *
 * \param pktop     The context to initialize.
 * 
 * \return          0 on success, error code on failure 
  */
int mbed_pk_init(mbed_pktop_t **pktop, mbed_rng_cb_t  rng_cb, mbed_entropy_cb_t entropy_cb, const char *seed_str); 


/**
 * \brief           Free the components of a #pktop.
 *
 * \param pktop The context to clear. It must have been initialized.
 *                  If this is \c NULL, this function does nothing.
 *
 * \note            For contexts that have been set up with
 *                  mbedtls_pk_setup_opaque(), this does not free the underlying
 *                  PSA key and you still need to call psa_destroy_key()
 *                  independently if you want to destroy that key.
 */
void *mbed_pk_free(mbed_pktop_t *pktop);



/**
 * \brief           Verify signature, with options.
 *                  (Includes verification of the padding depending on type.)
 *
 * \param topctx    The PK top context to use. It must be setup.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 * \param options   Pointer to type-specific options, or NULL
 * 
 * \return          0 on success (signature is valid),
 *                  #MBEDTLS_ERR_PK_TYPE_MISMATCH if the PK context can't be
 *                  used for this type of signatures,
 *                  #MBEDTLS_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in sig but its length is less than \p siglen,
 *                  or a specific error code.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be MBEDTLS_MD_NONE, only if hash_len != 0
 *
 * \note            If type is MBEDTLS_PK_RSASSA_PSS, then options must point
 *                  to a mbedtls_pk_rsassa_pss_options structure,
 *                  otherwise it must be NULL.
 */
int mbed_pk_verify_ext( mbed_pktop_t *pktop, mbed_hybpk_t pktype, mbed_md_alg_e  md_alg, 
                        const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len, const void *options );

int mbed_pk_verify_ext_old(mbed_pktop_t *pktop_ref, mbed_md_alg_e  md_alg, const uint8_t *hash, size_t hash_len,
                           const uint8_t *sig, size_t sig_len, const void *options );


/**
 * \brief           Restartable version of \c mbed_pk_verify()
 *
 * \note            Performs the same job as \c mbed_pk_verify(), but can
 *                  return early and restart according to the limit set with
 *                  \c mbedtls_ecp_set_max_ops() to reduce blocking for ECC
 *                  operations. For RSA, same as \c mbed_pk_verify().
 *
 * \param ctx       The PK context to use. It must have been set up.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 * \param rs_ctx    Restart context (NULL to disable restart)
 *
 * \return          See \c mbed_pk_verify(), or
 * \return          #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c mbedtls_ecp_set_max_ops().
 */
int mbed_pk_verify_restartable( mbed_pktop_t *pktop, mbed_md_alg_e md_alg, const uint8_t *hash, size_t hash_len,
                                const uint8_t *sig, size_t sig_len, mbedtls_pk_restart_ctx *rs_ctx );


/**
 * \brief           Verify signature (including padding if relevant).
 *
 * \param ctx       The PK context to use. It must have been set up.
 * \param md_alg    Hash algorithm used.
 *                  This can be #MBEDTLS_MD_NONE if the signature algorithm
 *                  does not rely on a hash algorithm (non-deterministic
 *                  ECDSA, RSA PKCS#1 v1.5).
 *                  For PKCS#1 v1.5, if \p md_alg is #MBEDTLS_MD_NONE, then
 *                  \p hash is the DigestInfo structure used by RFC 8017
 *                  &sect;9.2 steps 3&ndash;6. If \p md_alg is a valid hash
 *                  algorithm then \p hash is the digest itself, and this
 *                  function calculates the DigestInfo encoding internally.
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  #MBEDTLS_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in sig but its length is less than \p siglen,
 *                  or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  Use \c mbed_pk_verify_ext( MBEDTLS_PK_RSASSA_PSS, ... )
 *                  to verify RSASSA_PSS signatures.
 */
int mbed_pk_verify( mbed_pktop_t *pktop, mbed_md_alg_e md_alg, const uint8_t *hash, size_t hash_len,
                       const uint8_t *sig, size_t sig_len );


/**
 * \brief           Restartable version of \c mbed_pk_sign()
 *
 * \note            Performs the same job as \c mbed_pk_sign(), but can
 *                  return early and restart according to the limit set with
 *                  \c mbedtls_ecp_set_max_ops() to reduce blocking for ECC
 *                  operations. For RSA, same as \c mbed_pk_sign().
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param md_alg    Hash algorithm used (see notes for mbed_pk_sign())
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length
 * \param sig       Place to write the signature.
 *                  It must have enough room for the signature.
 *                  #MBEDTLS_PK_SIGNATURE_MAX_SIZE is always enough.
 *                  You may use a smaller buffer if it is large enough
 *                  given the key type.
 * \param sig_size  The size of the \p sig buffer in bytes.
 * \param sig_len   On successful return,
 *                  the number of bytes written to \p sig.
 * \param f_rng     RNG function, must not be \c NULL.
 * \param p_rng     RNG parameter
 * \param rs_ctx    Restart context (NULL to disable restart)
 *
 * \return          See \c mbed_pk_sign().
 * \return          #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c mbedtls_ecp_set_max_ops().
 */
int mbed_pk_sign_restartable( mbed_pktop_t *pktop,  mbed_md_alg_e md_alg, const uint8_t *hash, size_t hash_len,
                              uint8_t *sig, size_t sig_size, size_t *sig_len, mbedtls_pk_restart_ctx *rs_ctx );


/**
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hlen      Hash length
 * \param sig       Place to write the signature.
 *                  It must have enough room for the signature.
 *                  #MBEDTLS_PK_SIGNATURE_MAX_SIZE is always enough.
 *                  You may use a smaller buffer if it is large enough
 *                  given the key type.
 * \param sig_size  The size of the \p sig buffer in bytes.
 * \param sig_len   On successful return,
 *                  the number of bytes written to \p sig.
 *
 * \return          0 on success, or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0.
 *                  For ECDSA, md_alg may never be MBEDTLS_MD_NONE.
 */
int mbed_pk_sign( mbed_pktop_t *pktop, mbed_md_alg_e md_alg, const uint8_t *hash, size_t hlen,
                     uint8_t *sig, size_t sigsize, size_t *siglen);



/**
 * \brief           Decapsulate message (including padding if
 *                  relevant).
 *
 * \param topctx    The PK context to use. It must have been 
 *                  set up with a private key.
 * \param mode      Encapsulation mode (e.g. (PKCS#1 or OEAP) 
 * \param in        Input data to decrypt
 * \param ilen      Input size
 * \param out       Decrypted output data 
 * \param olen      Decrypted output data length
 * \param osize     Size of the output buffer
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int mbed_pk_decap( mbed_pktop_t *pktop, mbed_capmode_e mode, const uint8_t *in, size_t ilen, 
                   uint8_t *out, size_t osize, size_t *olen);


/**
 * \brief           Encapsulate message (including padding if 
 *                  relevant).
 *
 * \param ctx       The PK context to use. It must have been set up. 
 * \param mode      Encapsulation mode (e.g. (PKCS#1 or OEAP) 
 * \param in        Message to encrypt
 * \param ilen      Message size
 * \param out       Encrypted output
 * \param olen      Encrypted output length
 * \param osize     Size of the output buffer
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int mbed_pk_encap( mbed_pktop_t *pktop, mbed_capmode_e mode, const uint8_t *in, size_t ilen, 
                   uint8_t *out, size_t osize, size_t *olen);

// TODO header 
int mbed_pk_dh( mbed_pktop_t *pktop_prv_ref, mbed_pktop_t *pktop_peer_ref, uint8_t *shared, size_t size, size_t *olen);


/**
 * \brief           Check if a public-private pair of keys matches.
 *
 * \param pub       Context holding a public key.
 * \param prv       Context holding a private (and public) key.
 * \param f_rng     RNG function, must not be \c NULL.
 * \param p_rng     RNG parameter
 *
 * \return          \c 0 on success (keys were checked and match each other).
 * \return          #MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE if the keys could not
 *                  be checked - in that case they may or may not match.
 * \return          #MBEDTLS_ERR_PK_BAD_INPUT_DATA if a context is invalid.
 * \return          Another non-zero value if the keys do not match.
 */
int mbed_pk_check_pair( mbed_pktop_t *pktop_ref_pub, mbed_pktop_t *pktop_ref_prv);

// TODO: Add header 
int  mbed_pk_get_signature_oid( mbed_pktop_t *pktop_ref, mbed_md_alg_e mdtype, const char **oid, size_t *oid_len );


/**
 * \brief           Get the size in bits of the underlying key 
 *                  defined by the kye index.
 *
 * \param pktop The context to query. It must be initialized
 * \param key_idx   Index of the key within the hybrid key
 *
 * \return          Key size in bits, or 0 on error
 */
int              mbed_pk_get_bitlen_single( mbed_pktop_t *pktop, int key_idx, size_t *bitlen);
mbed_nistlevel_e mbed_pk_get_nist_level( mbed_pktop_t *pktop_ref, int key_idx);
size_t           mbed_pk_get_bitlen( mbed_pktop_t *pktop_ref); 




/**
 * \brief           Access the type name
 *
 * \param ctx       The PK context to use. It must have been initialized.
 *
 * \return          Type name on success, or "invalid PK"
 */
int mbed_pk_get_name( mbed_pktop_t *pktop, int key_idx, const char **name );



/**
 * \brief             Get the key type
 *
 * \param pktop   PK context to use. It must be initialized 
 *         
 * 
 * \return            Type on success.
 * \return            #MBEDTLS_PK_NONE for a context that is not
 */

// Todo add header 
int    mbed_pk_keygen( mbed_pktop_t *pktop, mbed_pktype_e pktype, char *keygen_params);
int    mbed_pk_can_do_single( mbed_pktop_t *pktop, mbed_pktype_e pktype_cmp);

int    mbed_pk_get_numkeys( mbed_pktop_t *pktop, int *num_keys );                                                                       
int    mbed_pk_parse_subpubkey( mbed_pktop_t *pktop, uint8_t **p, const uint8_t *end );                                              
int    mbed_pk_parse_pubkey_ssl( mbed_pktop_t *pktop_ref, mbed_pktarget_e target, mbed_hybpk_t pktype, uint8_t **p, const uint8_t *end );
int    mbed_pk_can_do( mbed_pktop_t *pktop, mbed_hybpk_t hybpk_alg_cmp); 
int    mbed_pk_parse_prv_keyfile(mbed_pktop_t *pktop, const char *path, const char *pwd); 
int    mbed_pk_parse_pub_keyfile(mbed_pktop_t *pktop, const char *path); 
int    mbed_pk_export_key_info( mbed_pktop_t *pktop_ref, mbed_pktarget_e target, mbed_pkexport_e level, char *buf, size_t size);
int    mbed_pk_write_key_info( mbed_pktop_t *pktop_ref, mbed_pktarget_e target, mbed_pkexport_e level, FILE *f);
int    mbed_pk_kem_extract( mbed_pktop_t *pktop_prv_ref, mbed_capmode_e capmode, size_t sh_blocksz,
                            uint8_t *shared, size_t sh_size, size_t *sh_olen, uint8_t *ibuf, size_t isize, size_t *ilen); 
int    mbed_pk_kem_gen( mbed_pktop_t *pktop_prv_ref, mbed_pktop_t *pktop_peer_ref, mbed_capmode_e capmode, size_t sh_blocksz, 
                        uint8_t *shared, size_t sh_size, size_t *sh_olen, uint8_t *obuf, size_t osize, size_t *olen); 

size_t mbed_pk_get_hybrid_len( mbed_pktop_t *pktop_ref); 
char*  mbed_pk_get_hybrid_name( mbed_pktop_t *pktop );                                                                                   

int    mbed_pk_get_ec_grpid( mbed_pktop_t *pktop, int key_idx, mbedtls_ecp_group_id *grpid );   // This needs to deprecated             


// Functions to be deprecated 
int mbed_pk_get_type( mbed_pktop_t *pktop, int key_idx, mbed_pktype_e *pktype);


mbedtls_ecp_keypair *mbed_get_eckey_ctx ( mbed_pktop_t *pktop_ref); 
mbed_hybpk_t         mbed_pk_get_type_old( mbed_pktop_t *pktop);
void                *mbed_pk_get_pkctx_old( mbed_pktop_t *pktop); 
mbedtls_ecp_keypair *mbedtls_pk_ec(mbed_pktop_t *pktop_ref); 
mbedtls_rsa_context *mbedtls_pk_rsa(mbed_pktop_t *pktop_ref);
size_t               mbedtls_pk_get_bitlen (mbed_pktop_t *pktop_ref ); 
int                  mbedtls_pk_setup( mbed_pktop_t *pktop_ref, mbed_hybpk_t pktype);
int                  mbedtls_pk_can_do( mbed_pktop_t *pktop_ref, mbed_hybpk_t pk_alg); 
static inline size_t mbedtls_pk_get_len( mbed_pktop_t *ctx )
{
    return( ( mbedtls_pk_get_bitlen( ctx ) + 7 ) / 8 );
}
int mbedtls_pk_sign_restartable( mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, size_t hash_len,  
                                 unsigned char *sig, size_t sig_size, size_t *sig_len, 
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, mbedtls_pk_restart_ctx *rs_ctx );
int mbedtls_pk_sign( mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, size_t hash_len,  
                     unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_verify_restartable( mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, 
                                   size_t hash_len, const unsigned char *sig, size_t sig_len, mbedtls_pk_restart_ctx *rs_ctx );
int mbedtls_pk_verify( mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, const unsigned char *hash, 
                                   size_t hash_len, const unsigned char *sig, size_t sig_len);
int mbedtls_pk_verify_ext( mbed_hybpk_t pktype, const void *options, mbed_pktop_t *pktop_ref, mbed_md_alg_e md_alg, 
                           const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len );

int mbedtls_pk_encrypt( mbed_pktop_t *pktop_ref, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
int mbedtls_pk_decrypt( mbed_pktop_t *pktop_ref, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
int mbedtls_pk_check_pair( mbed_pktop_t *pktop_pub, mbed_pktop_t *pktop_prv, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ); 
int mbedtls_pk_parse_key( mbed_pktop_t *pktop_ref, const unsigned char *key, size_t keylen,  const unsigned char *pwd, size_t pwdlen,
                          int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
int mbedtls_pk_parse_keyfile(mbed_pktop_t *pktop_ref, const char *path, const char *pwd, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
int mbedtls_pk_parse_public_key( mbed_pktop_t *pktop_ref, const unsigned char *key, size_t keylen);
int mbedtls_pk_parse_public_keyfile(mbed_pktop_t *pktop_ref, const char *path); 
int mbedtls_pk_write_key_der( mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size );
int mbedtls_pk_write_pubkey_der( mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size );
int mbedtls_pk_write_key_pem( mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size );
int mbedtls_pk_write_pubkey_pem( mbed_pktop_t *pktop_ref, unsigned char *buf, size_t size );\
const char * mbedtls_pk_get_name( mbed_pktop_t *pktop_ref ); 



/**
 * \brief             Export debug information
 *
 * \param pktop   The top PK context to use. It must have been initialized.
 * \param items       Place to write debug items
 *
 * \return            0 on success or MBEDTLS_ERR_PK_BAD_INPUT_DATA
 */
int mbed_pk_debug( mbed_pktop_t *pktop, int key_idx, mbedtls_pk_debug_item *items );



#if defined(MBEDTLS_PK_PARSE_C)
  /** \ingroup pk_module */
  /**
   * \brief           Parse a private key in PEM or DER format
   *
   * \param ctx       The PK context to fill. It must have been initialized
   *                  but not set up.
   * \param key       Input buffer to parse.
   *                  The buffer must contain the input exactly, with no
   *                  extra trailing material. For PEM, the buffer must
   *                  contain a null-terminated string.
   * \param keylen    Size of \b key in bytes.
   *                  For PEM data, this includes the terminating null byte,
   *                  so \p keylen must be equal to `strlen(key) + 1`.
   * \param pwd       Optional password for decryption.
   *                  Pass \c NULL if expecting a non-encrypted key.
   *                  Pass a string of \p pwdlen bytes if expecting an encrypted
   *                  key; a non-encrypted key will also be accepted.
   *                  The empty password is not supported.
   * \param pwdlen    Size of the password in bytes.
   *                  Ignored if \p pwd is \c NULL.
   *
   * \note            On entry, ctx must be empty, either freshly initialised
   *                  with mbedtls_pk_init() or reset with mbed_pk_free(). If you need a
   *                  specific key type, check the result with mbed_pk_can_do().
   *
   * \note            The key is also checked for correctness.
   *
   * \return          0 if successful, or a specific PK or PEM error code
   */
  int mbed_pk_parse_prvkey( mbed_pktop_t *pktop, const uint8_t *key, size_t keylen, const uint8_t *pwd, size_t pwdlen);



  /** \ingroup pk_module */
  /**
   * \brief           Parse a public key in PEM or DER format
   *
   * \param ctx       The PK context to fill. It must have been initialized
   *                  but not set up.
   * \param key       Input buffer to parse.
   *                  The buffer must contain the input exactly, with no
   *                  extra trailing material. For PEM, the buffer must
   *                  contain a null-terminated string.
   * \param keylen    Size of \b key in bytes.
   *                  For PEM data, this includes the terminating null byte,
   *                  so \p keylen must be equal to `strlen(key) + 1`.
   *
   * \note            On entry, ctx must be empty, either freshly initialised
   *                  with mbedtls_pk_init() or reset with mbed_pk_free(). If you need a
   *                  specific key type, check the result with mbed_pk_can_do().
   *
   * \note            The key is also checked for correctness.
   *
   * \return          0 if successful, or a specific PK or PEM error code
   */
  int mbed_pk_parse_pubkey( mbed_pktop_t *pktop, const uint8_t *key, size_t keylen );
  int mbed_pk_parse_pubkey_ssl( mbed_pktop_t *pktop_ref, mbed_pktarget_e target, mbed_hybpk_t pktype, uint8_t **p, const uint8_t *end);
  
  #if defined(MBEDTLS_PK_WRITE_C)
    /**
     * \brief           Write a private key to a PKCS#1 or SEC1 DER structure
     *                  Note: data is written at the end of the buffer! Use the
     *                        return value to determine where you should start
     *                        using the buffer
     *
     * \param ctx       PK context which must contain a valid private key.
     * \param buf       buffer to write to
     * \param size      size of the buffer
     *
     * \return          length of data written if successful, or a specific
     *                  error code
     */
    int mbed_pk_write_key_der( mbed_pktop_t *pktop, uint8_t *buf, size_t size );

    /**
     * \brief           Write a public key to a SubjectPublicKeyInfo DER structure
     *                  Note: data is written at the end of the buffer! Use the
     *                        return value to determine where you should start
     *                        using the buffer
     *
     * \param ctx       PK context which must contain a valid public or private key.
     * \param buf       buffer to write to
     * \param size      size of the buffer
     *
     * \return          length of data written if successful, or a specific
     *                  error code
     */
    int mbed_pk_write_pubkey_der(mbed_pktop_t *pktop, uint8_t *buf, size_t size);

    // TODO: header 
    int mbed_pk_write_pubkey_ssl( mbed_pktop_t *pktop_ref, uint8_t *buf, size_t size, size_t *olen); 

    #if defined(MBEDTLS_PEM_WRITE_C)
      /**
       * \brief           Write a public key to a PEM string
       *
       * \param ctx       PK context which must contain a valid public or private key.
       * \param buf       Buffer to write to. The output includes a
       *                  terminating null byte.
       * \param size      Size of the buffer in bytes.
       *
       * \return          length of PEM data if successful, or a specific error code
       */
      int mbed_pk_write_pubkey_pem(mbed_pktop_t *pktop, uint8_t *buf, size_t size);

      /**
       * \brief           Write a private key to a PKCS#1 or SEC1 PEM string
       *
       * \param ctx       PK context which must contain a valid private key.
       * \param buf       Buffer to write to. The output includes a
       *                  terminating null byte.
       * \param size      Size of the buffer in bytes.
       *
      * \return          length of PEM data if successful, or a specific error code
       */
      int mbed_pk_write_key_pem(mbed_pktop_t *pktop, uint8_t *buf, size_t size);
    #endif /* MBEDTLS_PEM_WRITE_C */
  #endif /* MBEDTLS_PK_WRITE_C */
#endif /* MBEDTLS_PK_PARSE_C */


#if defined(MBEDTLS_PK_WRITE_C)

  #if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  /**
   * \brief           Initialize a restart context
   *
   * \param ctx       The context to initialize.
   *                  This must not be \c NULL.
   */
  void mbedtls_pk_restart_init( mbedtls_pk_restart_ctx *ctx );

  /**
   * \brief           Free the components of a restart context
   *
   * \param ctx       The context to clear. It must have been initialized.
   *                  If this is \c NULL, this function does nothing.
   */
  void mbedtls_pk_restart_free( mbedtls_pk_restart_ctx *ctx );
  #endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */


#endif /* MBEDTLS_PK_WRITE_C */

#if defined(MBEDTLS_FS_IO)
//TODO add header 
int mbed_pk_load_file( const char *path, uint8_t **buf, size_t *n ); 
#endif 


#ifdef __cplusplus
}
#endif  // from: __cplusplus

#endif /* MBEDTLS_PKPQ_H */
