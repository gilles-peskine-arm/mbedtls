#include "common.h"

#if defined(MBEDTLS_PK_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include "pkpq.h"

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define DILITHIUM_MODE  3   // default 

#define MBED_DILITHIUM_2_LENGTH_PUBLIC_KEY  1312
#define MBED_DILITHIUM_2_LENGTH_SECRET_KEY  2528
#define MBED_DILITHIUM_2_LENGTH_SIGNATURE   2420

#define MBED_DILITHIUM_3_LENGTH_PUBLIC_KEY  1952
#define MBED_DILITHIUM_3_LENGTH_SECRET_KEY  4000
#define MBED_DILITHIUM_3_LENGTH_SIGNATURE   3293

#define MBED_DILITHIUM_5_LENGTH_PUBLIC_KEY  2592
#define MBED_DILITHIUM_5_LENGTH_SECRET_KEY  4864
#define MBED_DILITHIUM_5_LENGTH_SIGNATURE   4595



//----------------------------------------------------------------------------
//----------------- type_defines ---------------------------------------------
//----------------------------------------------------------------------------
#if 0
OQS_SIG *MBED_dilithium_2_new() {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	sig->method_name = MBED_alg_dilithium_2;
	sig->alg_version = "https://github.com/pq-crystals/dilithium/commit/d9c885d3f2e11c05529eeeb7d70d808c972b8409";

	sig->claimed_nist_level = 2;
	sig->euf_cma = true;

	sig->length_PUBLIC_KEY = MBED_DILITHIUM_2_LENGTHpublic_key;
	sig->length_SECRET_KEY = MBED_DILITHIUM_2_LENGTHsecret_key;
	sig->length_SIGNATURE = MBED_DILITHIUM_2_LENGTHsignature;

	sig->keypair = MBED_dilithium_2_keypair;
	sig->sign = MBED_dilithium_2_sign;
	sig->verify = MBED_dilithium_2_verify;

	return sig;
#endif 

typedef struct
{
     int K;
     int L;             
     int ETA;              
     int TAU;              
     int BETA;
     int GAMMA1; 
     int GAMMA2;
     int OMEGA; 
} dilparams_t; 

typedef struct
{
    uint8_t        *sk;          // secret key 
    uint8_t        *pk;          // public key 
    size_t          pk_len;  
    size_t          sk_len;  
    dilparams_t     dil_params;      // Dilithium Params

    // --- Common for all key algorithms 
    pk_keyparams_t  key_params;  
    pkfull_t       *pkfull;      // Pointer back to the full key context 
    void           *pktop;       // Pointer back to the top key context 
} dilkey_t;

#endif /* MBEDTLS_PK_C */
