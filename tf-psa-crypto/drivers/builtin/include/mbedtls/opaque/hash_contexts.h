/**
 * \file hash_contexts.h
 *
 * \brief Operation contexts for hashes.
 *
 * \note The contents of this file are not part of the stable interface of
 *       the library. This file defines the implementation of structure
 *       types. These types are not part of the API, but they are part
 *       of the ABI, so the library SO version must be incremented when
 *       the types change.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_OPAQUE_HASH_CONTEXTS_H
#define MBEDTLS_OPAQUE_HASH_CONTEXTS_H
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mbedtls_md5_context {
    uint32_t MBEDTLS_PRIVATE(total)[2];          /*!< number of bytes processed  */
    uint32_t MBEDTLS_PRIVATE(state)[4];          /*!< intermediate digest state  */
    unsigned char MBEDTLS_PRIVATE(buffer)[64];   /*!< data block being processed */
};

struct mbedtls_ripemd160_context {
    uint32_t MBEDTLS_PRIVATE(total)[2];          /*!< number of bytes processed  */
    uint32_t MBEDTLS_PRIVATE(state)[5];          /*!< intermediate digest state  */
    unsigned char MBEDTLS_PRIVATE(buffer)[64];   /*!< data block being processed */
};

struct mbedtls_sha1_context {
    uint32_t MBEDTLS_PRIVATE(total)[2];          /*!< The number of Bytes processed.  */
    uint32_t MBEDTLS_PRIVATE(state)[5];          /*!< The intermediate digest state.  */
    unsigned char MBEDTLS_PRIVATE(buffer)[64];   /*!< The data block being processed. */
};

struct mbedtls_sha256_context {
    unsigned char MBEDTLS_PRIVATE(buffer)[64];   /*!< The data block being processed. */
    uint32_t MBEDTLS_PRIVATE(total)[2];          /*!< The number of Bytes processed.  */
    uint32_t MBEDTLS_PRIVATE(state)[8];          /*!< The intermediate digest state.  */
#if defined(MBEDTLS_SHA224_C)
    int MBEDTLS_PRIVATE(is224);                  /*!< Determines which function to use:
                                                    0: Use SHA-256, or 1: Use SHA-224. */
#endif
};

struct mbedtls_sha512_context {
    uint64_t MBEDTLS_PRIVATE(total)[2];          /*!< The number of Bytes processed. */
    uint64_t MBEDTLS_PRIVATE(state)[8];          /*!< The intermediate digest state. */
    unsigned char MBEDTLS_PRIVATE(buffer)[128];  /*!< The data block being processed. */
#if defined(MBEDTLS_SHA384_C)
    int MBEDTLS_PRIVATE(is384);                  /*!< Determines which function to use:
                                                      0: Use SHA-512, or 1: Use SHA-384. */
#endif
};

/* Note: these are aligned with the definitions of PSA_ALG_ macros for hashes,
 * in order to enable an efficient implementation of conversion functions.
 * This is tested by md_to_from_psa() in test_suite_md. */
enum mbedtls_md_type_t {
    MBEDTLS_MD_NONE=0,    /**< None. */
    MBEDTLS_MD_MD5=0x03,       /**< The MD5 message digest. */
    MBEDTLS_MD_RIPEMD160=0x04, /**< The RIPEMD-160 message digest. */
    MBEDTLS_MD_SHA1=0x05,      /**< The SHA-1 message digest. */
    MBEDTLS_MD_SHA224=0x08,    /**< The SHA-224 message digest. */
    MBEDTLS_MD_SHA256=0x09,    /**< The SHA-256 message digest. */
    MBEDTLS_MD_SHA384=0x0a,    /**< The SHA-384 message digest. */
    MBEDTLS_MD_SHA512=0x0b,    /**< The SHA-512 message digest. */
    MBEDTLS_MD_SHA3_224=0x10,  /**< The SHA3-224 message digest. */
    MBEDTLS_MD_SHA3_256=0x11,  /**< The SHA3-256 message digest. */
    MBEDTLS_MD_SHA3_384=0x12,  /**< The SHA3-384 message digest. */
    MBEDTLS_MD_SHA3_512=0x13,  /**< The SHA3-512 message digest. */
};

#ifdef __cplusplus
}
#endif

#endif /* hash_contexts.h */
