/**
 * \file cipher_contexts.h
 *
 * \brief Operation contexts for cipher primitives.
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
#ifndef MBEDTLS_OPAQUE_CIPHER_CONTEXTS_H
#define MBEDTLS_OPAQUE_CIPHER_CONTEXTS_H
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mbedtls_aes_context {
    int MBEDTLS_PRIVATE(nr);                     /*!< The number of rounds. */
    size_t MBEDTLS_PRIVATE(rk_offset);           /*!< The offset in array elements to AES
                                                    round keys in the buffer. */
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    uint32_t MBEDTLS_PRIVATE(buf)[44];           /*!< Aligned data buffer to hold
                                                    10 round keys for 128-bit case. */
#else
    uint32_t MBEDTLS_PRIVATE(buf)[68];           /*!< Unaligned data buffer. This buffer can
                                                    hold 32 extra Bytes, which can be used for
                                                    simplifying key expansion in the 256-bit
                                                    case by generating an extra round key. */
#endif /* MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
};

struct mbedtls_aes_xts_context {
    struct mbedtls_aes_context MBEDTLS_PRIVATE(crypt); /*!< The AES context to use for AES block
                                                   encryption or decryption. */
    struct mbedtls_aes_context MBEDTLS_PRIVATE(tweak); /*!< The AES context used for tweak
                                                   computation. */
};

#define MBEDTLS_ARIA_BLOCKSIZE   16 /**< ARIA block size in bytes. */
#define MBEDTLS_ARIA_MAX_ROUNDS  16 /**< Maximum number of rounds in ARIA. */
#define MBEDTLS_ARIA_MAX_KEYSIZE 32 /**< Maximum size of an ARIA key in bytes. */

struct mbedtls_aria_context {
    unsigned char MBEDTLS_PRIVATE(nr);           /*!< The number of rounds (12, 14 or 16) */
    /*! The ARIA round keys. */
    uint32_t MBEDTLS_PRIVATE(rk)[MBEDTLS_ARIA_MAX_ROUNDS + 1][MBEDTLS_ARIA_BLOCKSIZE / 4];
};

struct mbedtls_camellia_context {
    int MBEDTLS_PRIVATE(nr);                     /*!<  number of rounds  */
    uint32_t MBEDTLS_PRIVATE(rk)[68];            /*!<  CAMELLIA round keys    */
};

struct mbedtls_chacha20_context {
    uint32_t MBEDTLS_PRIVATE(state)[16];          /*! The state (before round operations). */
    uint8_t  MBEDTLS_PRIVATE(keystream8)[64];     /*! Leftover keystream bytes. */
    size_t MBEDTLS_PRIVATE(keystream_bytes_used); /*! Number of keystream bytes already used. */
};

struct mbedtls_poly1305_context {
    uint32_t MBEDTLS_PRIVATE(r)[4];      /** The value for 'r' (low 128 bits of the key). */
    uint32_t MBEDTLS_PRIVATE(s)[4];      /** The value for 's' (high 128 bits of the key). */
    uint32_t MBEDTLS_PRIVATE(acc)[5];    /** The accumulator number. */
    uint8_t MBEDTLS_PRIVATE(queue)[16];  /** The current partial block of data. */
    size_t MBEDTLS_PRIVATE(queue_len);   /** The number of bytes stored in 'queue'. */
};

enum mbedtls_chachapoly_mode_t {
    MBEDTLS_CHACHAPOLY_ENCRYPT,     /**< The mode value for performing encryption. */
    MBEDTLS_CHACHAPOLY_DECRYPT      /**< The mode value for performing decryption. */
};

struct mbedtls_chachapoly_context {
    struct mbedtls_chacha20_context MBEDTLS_PRIVATE(chacha20_ctx);  /**< The ChaCha20 context. */
    struct mbedtls_poly1305_context MBEDTLS_PRIVATE(poly1305_ctx);  /**< The Poly1305 context. */
    uint64_t MBEDTLS_PRIVATE(aad_len);                       /**< The length (bytes) of the Additional Authenticated Data. */
    uint64_t MBEDTLS_PRIVATE(ciphertext_len);                /**< The length (bytes) of the ciphertext. */
    int MBEDTLS_PRIVATE(state);                              /**< The current state of the context. */
    enum mbedtls_chachapoly_mode_t MBEDTLS_PRIVATE(mode);         /**< Cipher mode (encrypt or decrypt). */
};

struct mbedtls_des_context {
    uint32_t MBEDTLS_PRIVATE(sk)[32];            /*!<  DES subkeys       */
};

struct mbedtls_des3_context {
    uint32_t MBEDTLS_PRIVATE(sk)[96];            /*!<  3DES subkeys      */
};

enum mbedtls_cipher_id_t {
    MBEDTLS_CIPHER_ID_NONE = 0,  /**< Placeholder to mark the end of cipher ID lists. */
    MBEDTLS_CIPHER_ID_NULL,      /**< The identity cipher, treated as a stream cipher. */
    MBEDTLS_CIPHER_ID_AES,       /**< The AES cipher. */
    MBEDTLS_CIPHER_ID_DES,       /**< The DES cipher. \warning DES is considered weak. */
    MBEDTLS_CIPHER_ID_3DES,      /**< The Triple DES cipher. \warning 3DES is considered weak. */
    MBEDTLS_CIPHER_ID_CAMELLIA,  /**< The Camellia cipher. */
    MBEDTLS_CIPHER_ID_ARIA,      /**< The Aria cipher. */
    MBEDTLS_CIPHER_ID_CHACHA20,  /**< The ChaCha20 cipher. */
};

#ifdef __cplusplus
}
#endif

#endif /* cipher_contexts.h */
