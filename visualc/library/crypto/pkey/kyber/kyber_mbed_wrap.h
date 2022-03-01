#include "common.h"

#if defined(MBEDTLS_PK_C)

//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include "pkpq.h"

//----------------------------------------------------------------------------
//----------------- Defines --------------------------------------------------
//----------------------------------------------------------------------------
#define KYBER_MODE  3   // default 

#define MBED_PK_KYBER_512_LENGTH_PUBLIC_KEY       800
#define MBED_PK_KYBER_512_LENGTH_SECRET_KEY      1632
#define MBED_PK_KYBER_512_LENGTH_CIPHERTEXT       768
#define MBED_PK_KYBER_512_LENGTH_SHARED_SECRET     32

#define MBED_PK_KYBER_768_LENGTH_PUBLIC_KEY      1184
#define MBED_PK_KYBER_768_LENGTH_SECRET_KEY      2400
#define MBED_PK_KYBER_768_LENGTH_CIPHERTEXT      1088
#define MBED_PK_KYBER_768_LENGTH_SHARED_SECRET     32

#define MBED_PK_KYBER_1024_LENGTH_PUBLIC_KEY     1568
#define MBED_PK_KYBER_1024_LENGTH_SECRET_KEY     3168
#define MBED_PK_KYBER_1024_LENGTH_CIPHERTEXT     1568
#define MBED_PK_KYBER_1024_LENGTH_SHARED_SECRET    32


//----------------------------------------------------------------------------
//----------------- type_defines ---------------------------------------------
//----------------------------------------------------------------------------

typedef struct
{
     int ETA;         
     int KYBER_POLYCOMPRESSEDBYTES;
     int KYBER_POLYVECCOMPRESSEDBYTES;
} kybparams_t;


typedef struct
{
    uint8_t        *sk;          // Secret key  
    uint8_t        *pk;          // Public key 
    size_t          pk_len;      // public key length   
    size_t          sk_len;      // secret key length 
    kybparams_t     kyb_params;  // Kyber Paramaters

    // --- Common for all key algorithms 
    pk_keyparams_t  key_params;  // generic key params (name, oid, key lengths, security strengths etc) 
    pkfull_t       *pkfull;      // Pointer back to the full KEY context 
    void           *pktop;       // Pointer back to the top KEY context 
} kybkey_t;


#endif /* MBEDTLS_PK_C */
