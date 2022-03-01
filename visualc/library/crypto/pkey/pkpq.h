/**
 * \file pkpq.h
 *
 * \brief Internal include file for the Public Key (pk) 
 *        abstraction layer with Post Quantum (pq) support.
 */

#ifndef __PKPQ_H__
#define __PKPQ_H__

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <stdint.h>

#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"


#ifdef __cplusplus
extern "C" {
#endif

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define PKEY_MAX_FULL_KEYS       3        // pktype limit is 4  
#define PKEY_MAX_SEEDSTR_LEN     128

#define PKEY_COMB_TYPE_SHIFT     8 
#define PKEY_COMB_TYPE_MASK      0xff 

//----------------------------------------------------------------------------
//----------------- Precompiler sanity check ---------------------------------
//----------------------------------------------------------------------------
#if (PKEY_MAX_FULL_KEYS > 4)
 #error "PKEY_MAX_FULL_KEYS maximum supported value is 4" 
#endif 

//----------------------------------------------------------------------------
//----------------- Enums and typedefs ---------------------------------------
//----------------------------------------------------------------------------
 // shorten names internally for often used types 
typedef mbed_pktype_e        pktype_e;     // public key algorithm type 
typedef mbed_md_alg_e        mdtype_e;     // message digest algorithm 
typedef mbed_capmode_e       capmode_e;    // en/decapsulate mode (PKCS1,OEAP,..) 
typedef mbed_pkexport_e      pkexport_e;   // PK export level/type DER,BASIC,EXTENDED or FULL 
typedef mbed_pktarget_e      pktarget_e;   // targeting public or private key  

typedef mbedtls_ecp_keypair  eckey_t;      // EC key context  (should be moved to EC subdir) 
typedef mbedtls_rsa_context  rsakey_t;     // RSA key context (should be moved to RSA subdir)
typedef mbedtls_asn1_buf     asn1buf_t;    // ASN1 buffer type 
typedef mbedtls_mpi          mpi_t;        // Multi precision integer  
typedef mbedtls_ecp_group_id ec_grpid_e;   // Elliptical curve group ID 

typedef mbed_entropy_cb_t    entropy_cb_t; // Entropy generator callback function 
typedef mbed_hybpk_t         hybpk_t;      // Combined type of all (sub)keys in a top level key. 
typedef mbed_nistlevel_e     nistlevel_e;  // NIST security levels  


typedef struct  
{
     const uint8_t  *start;    // start pointer of buffer 
     const uint8_t  *buf;
     const size_t    size;     // data size 
     size_t          iolen;    // data written or read 
} pkbuf_t;


// --- key specific information. (Note: 0 value means that the field is not populated.) 
typedef const struct pk_keyparams_s
{
    pktype_e     pktype;        // key type (RSA/EC etc.)                         
    size_t       pk_len;        // public key length                              
    size_t       sk_len;        // secret key length                              
    size_t       sig_len;       // Signature length     (sign/verify)             
    size_t       ct_len;        // cipher text length   (encap/decap)             
    size_t       ss_len;        // shared secret length (encap/decap or dh)       
    nistlevel_e  nist_level;    // NIST security level                            
    const char  *name;          // Key name                                       
    pkbuf_t      oid;           // OID associated with the key                    
    int          initialized;   // structure is initialized (optional)            
} pk_keyparams_t;

typedef const struct pk_rnginfo_s
{
    mbed_rng_cb_t       cb;            // random number generator callback func 
    void               *ctx;           // pointer to rng context 
    mbed_entropy_cb_t   entropy_cb;    // entropy callback func 
    void               *entropy;       // entropy context
    char               *seed_str;      // seed str
    size_t              seed_len;      // length of the seed str 
    int                 initialized;   // flag indicating it is initialized
} rnginfo_t;


// full key info for one key of the hybrid key struct 
typedef const struct pkfull_s
{
    const struct pkinfo_s  *pkinfo; 
    uint8_t                *pkctx;  
    const struct pktop_s   *pktop;       // pointer back to the top reference
    int                     is_pub;      // True if it is a public key
    nistlevel_e             nist_level; 
} pkfull_t;  


// Top level hybrid key info  
typedef const struct pktop_s
{
    pkfull_t   *pkfull_list[PKEY_MAX_FULL_KEYS];  // list of key pointer 
    rnginfo_t   rng_info;         // Random Number Generator information             
    hybpk_t     hybpk_alg;        // Combined pktype of all keys 
    int         num_keys;         // Number of key within the hybrid key 
    size_t      hyb_len;          // Hybrid key length. Is sum of individual key lengths, NOT very usefull
    //size_t      dh_len;           // Length of the Diffie Hellman key exchange size 
    int         is_pub;           // True if it is a public key 
    int         dsa_support;      // Supports Digital signatures 
    int         kem_support;      // Supports Key Exchange Mechanism (KEM)
    nistlevel_e nist_level;       // Combined NIST level (lowest value of individual keys) 
    char        hybrid_name[32];  // Key name 
} pktop_t;


typedef const struct pkinfo_s
{
    pktype_e        pktype;      // public key type ( TODO redundant remove) 
    //pkbuf_t        *oid;         // oid value expected in a PKCS8 formatted key 
    //const char     *name;        // return name of crypto alg type 
                                           
    pk_keyparams_t *(*get_keyparams)( void *);     // Get pointer to the key parameters  

    // Verify and sign functions 
    int (*vrfy_func) ( void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig_in, void* rs_info);
    int (*sign_func) ( void *pkctx, mdtype_e md_alg, pkbuf_t *hash, pkbuf_t *sig_out, void* rs_info);  

    //  decapsulate and encapsulate functions 
    int (*decap_func)( void *pkctx, capmode_e mode, pkbuf_t *m,  pkbuf_t *result);  
    int (*encap_func)( void *pkctx, capmode_e mode, pkbuf_t *m,  pkbuf_t *result);  

    // Calculate shared secret function
    int (*dh_func)( void *pkctx_prv, void *pkctx_peer, pkbuf_t *shared_secret); 

    int (*keygen_func)( void *pkctx, char* keygen_params);        // Key generation function 

    int (*check_pair_func)( void *pkctx_pub, void *pkctx_prv);    // check public/private key pair 
    void * (*ctx_alloc_func)( pkfull_t *pkfull);                  // allocate new key context 
    void * (*ctx_free_func)( void *pkctx );                       // free key context 

    // Import a DER formatted key (TODO: der_olen is redundant) 
    int (*import_func)( void *pkctx, pktarget_e target, pkbuf_t *buf, void *alg_info, size_t *der_olen);  
      // Export key in DER or text form 
    int (*export_func)( void *pkctx, pktarget_e target, pkexport_e level, pkbuf_t *buf); 
                                                                       
    // Interface with the debug module 
    void (*debug_func)( void *pkctx, mbedtls_pk_debug_item *items ); 
} pkinfo_t;



//----------------------------------------------------------------------------
//----------------- Function prototypes --------------------------------------
//----------------------------------------------------------------------------
int         pkey_can_do(pktype_e pktype, pktype_e pktype_cmp); 

pktype_e    pkey_get_type(pkfull_t *pkfull);
const char *pkey_get_name(pkfull_t *pkfull);
size_t      pkey_get_siglen(pkfull_t *pkfull);
size_t      pkey_get_sslen(pkfull_t *pkfull);
size_t      pkey_get_ctlen(pkfull_t *pkfull);

void       *pkey_free_pkfull( struct pkfull_s *pkfull); 
int         pkey_pkfull_setup(pkfull_t *pkfull, pktop_t *pktop, pktype_e pktype);
int         pkey_add_fullkey_to_list(pktop_t *pktop, pkfull_t *pkfull); 
int         pkey_get_rng_info( pktop_t *pktop, rnginfo_t **rng_out);

void        pkbuf_init(pkbuf_t *data, const uint8_t *buf, size_t size, size_t iolen);
void        pkbuf_extract(pkbuf_t *data, uint8_t **buf, size_t *size, size_t *iolen);
void        pkbuf_extract_const(pkbuf_t *data, const uint8_t **buf, size_t *size, size_t *iolen);
int         pkbuf_move(pkbuf_t *data, size_t len);
size_t      pkbuf_total_io(pkbuf_t *data);

int         pkey_register_pk_algorithm( pkinfo_t * pkinfo); 

// Functions depending on the pktype 
//pkinfo_t  *pkey_ec_get_pkinfo( pktype_e pktype); 
//pkinfo_t  *pkey_rsa_get_pkinfo( pktype_e pktype);
//pkinfo_t  *pkey_dilithium_get_pkinfo( pktype_e pktype);
//pkinfo_t  *pkey_kyber_get_pkinfo( pktype_e pktype); 

pkinfo_t  *pkey_pkinfo_from_type(pktype_e  pktype);

extern int pkey_eckey_enable_constructors; 
extern int pkey_rsakey_enable_constructors; 
extern int pkey_dilkey_enable_constructors; 
extern int pkey_kybkey_enable_constructors; 


#ifdef __cplusplus
}
#endif

#endif /* __PKPQ_H__ */
