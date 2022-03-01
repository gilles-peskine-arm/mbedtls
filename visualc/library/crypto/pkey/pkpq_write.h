/**
 * \file pkpq.h
 *
 * \brief Internal include file for the Public Key (pk) 
 *        abstraction layer with Post Quantum (pq) support.
 */

#ifndef __PKPQ_WRITE_H__
#define __PKPQ_WRITE_H__


#ifdef __cplusplus
extern "C" {
#endif
//----------------------------------------------------------------------------
//----------------- Includes -------------------------------------------------
//----------------------------------------------------------------------------
#include <stdint.h>

#include "pkpq.h"

//----------------------------------------------------------------------------
//----------------- Defines  -------------------------------------------------
//----------------------------------------------------------------------------
#if defined(MBEDTLS_PEM_WRITE_C)

  #define PEM_BEGIN_PUBLIC_KEY    "-----BEGIN PUBLIC KEY-----\n"
  #define PEM_END_PUBLIC_KEY      "-----END PUBLIC KEY-----\n"

  // hybrid generic key 
  #define PEM_BEGIN_PRIVATE_KEY       "-----BEGIN PRIVATE KEY-----\n"
  #define PEM_END_PRIVATE_KEY         "-----END PRIVATE KEY-----\n"

  #define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
  #define PEM_END_PRIVATE_KEY_RSA     "-----END RSA PRIVATE KEY-----\n"
  #define PEM_BEGIN_PRIVATE_KEY_EC    "-----BEGIN EC PRIVATE KEY-----\n"
  #define PEM_END_PRIVATE_KEY_EC      "-----END EC PRIVATE KEY-----\n"

  /*
   * Max sizes of key per types. Shown as tag + len (+ content).
   */

  #if defined(MBEDTLS_RSA_C)
    /*
     * RSA public keys:
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
     *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
     *                                                + 1 + 1 + 9 (rsa oid)
     *                                                + 1 + 1 (params null)
     *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
     *  RSAPublicKey ::= SEQUENCE {                     1 + 3
     *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
     *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
     *  }
     */
    #define RSA_PUB_DER_MAX_BYTES   ( 38 + 2 * MBEDTLS_MPI_MAX_SIZE )

    /*
     * RSA private keys:
     *  RSAPrivateKey ::= SEQUENCE {                    1 + 3
     *      version           Version,                  1 + 1 + 1
     *      modulus           INTEGER,                  1 + 3 + MPI_MAX + 1
     *      publicExponent    INTEGER,                  1 + 3 + MPI_MAX + 1
     *      privateExponent   INTEGER,                  1 + 3 + MPI_MAX + 1
     *      prime1            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
     *      prime2            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
     *      exponent1         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
     *      exponent2         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
     *      coefficient       INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL  0 (not supported)
     *  }
     */
    #define MPI_MAX_SIZE_2          ( MBEDTLS_MPI_MAX_SIZE / 2 + \
                                      MBEDTLS_MPI_MAX_SIZE % 2 )
    #define RSA_PRV_DER_MAX_BYTES   ( 47 + 3 * MBEDTLS_MPI_MAX_SIZE \
                                       + 5 * MPI_MAX_SIZE_2 )

  #else /* MBEDTLS_RSA_C */

    #define RSA_PUB_DER_MAX_BYTES   0
    #define RSA_PRV_DER_MAX_BYTES   0

  #endif /* MBEDTLS_RSA_C */

  #if defined(MBEDTLS_ECP_C)
    /*
     * EC public keys:
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
     *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
     *                                            + 1 + 1 + 7 (ec oid)
     *                                            + 1 + 1 + 9 (namedCurve oid)
     *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
     *                                            + 1 (point format)        [1]
     *                                            + 2 * ECP_MAX (coords)    [1]
     *  }
     */
    #define ECP_PUB_DER_MAX_BYTES   ( 30 + 2 * MBEDTLS_ECP_MAX_BYTES )

    /*
     * EC private keys:
     * ECPrivateKey ::= SEQUENCE {                  1 + 2
     *      version        INTEGER ,                1 + 1 + 1
     *      privateKey     OCTET STRING,            1 + 1 + ECP_MAX
     *      parameters [0] ECParameters OPTIONAL,   1 + 1 + (1 + 1 + 9)
     *      publicKey  [1] BIT STRING OPTIONAL      1 + 2 + [1] above
     *    }
     */
    #define ECP_PRV_DER_MAX_BYTES   ( 29 + 3 * MBEDTLS_ECP_MAX_BYTES )

  #else /* MBEDTLS_ECP_C */

    #define ECP_PUB_DER_MAX_BYTES   0
    #define ECP_PRV_DER_MAX_BYTES   0

  #endif /* MBEDTLS_ECP_C */

#endif  // #if defined(MBEDTLS_PEM_WRITE_C)

/*
#define PUB_DER_MAX_BYTES   ( RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                              RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES )
#define PRV_DER_MAX_BYTES   ( RSA_PRV_DER_MAX_BYTES > ECP_PRV_DER_MAX_BYTES ? \
                             RSA_PRV_DER_MAX_BYTES : ECP_PRV_DER_MAX_BYTES )
*/

// TODO: change to letting the algorithm determine its largest size 
#define PUB_DER_MAX_BYTES   ( 16*1024 )
#define PRV_DER_MAX_BYTES   ( 16*1024 )




//----------------------------------------------------------------------------
//----------------- Function prototypes --------------------------------------
//----------------------------------------------------------------------------
int   pkey_write_pubkey(pkfull_t *pkfull, uint8_t **p, uint8_t *start); 


#ifdef __cplusplus
}
#endif

#endif /* __PKPQ_WRITE_H__ */
