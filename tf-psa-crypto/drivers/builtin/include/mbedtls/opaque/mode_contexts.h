/**
 * \file mode_contexts.h
 *
 * \brief Operation contexts for symmetric modes.
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
#ifndef MBEDTLS_OPAQUE_MODE_CONTEXTS_H
#define MBEDTLS_OPAQUE_MODE_CONTEXTS_H
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* We don't support Camellia or ARIA in this module */
#if defined(MBEDTLS_AES_C)
#define MBEDTLS_CMAC_MAX_BLOCK_SIZE      16  /**< The longest block used by CMAC is that of AES. */
#else
#define MBEDTLS_CMAC_MAX_BLOCK_SIZE      8   /**< The longest block used by CMAC is that of 3DES. */
#endif

/**
 * The CMAC context structure.
 */
struct mbedtls_cmac_context_t {
    /** The internal state of the CMAC algorithm.  */
    unsigned char       MBEDTLS_PRIVATE(state)[MBEDTLS_CMAC_MAX_BLOCK_SIZE];

    /** Unprocessed data - either data that was not block aligned and is still
     *  pending processing, or the final block. */
    unsigned char       MBEDTLS_PRIVATE(unprocessed_block)[MBEDTLS_CMAC_MAX_BLOCK_SIZE];

    /** The length of data pending processing. */
    size_t              MBEDTLS_PRIVATE(unprocessed_len);
};

enum mbedtls_operation_t {
    MBEDTLS_OPERATION_NONE = -1,
    MBEDTLS_DECRYPT = 0,
    MBEDTLS_ENCRYPT,
};

/** Maximum length of any IV, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with MBEDTLS_SSL_MAX_IV_LENGTH defined
 * in library/ssl_misc.h. */
#define MBEDTLS_MAX_IV_LENGTH      16

/** Maximum block size of any cipher, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with MBEDTLS_SSL_MAX_BLOCK_LENGTH defined
 * in library/ssl_misc.h. */
#define MBEDTLS_MAX_BLOCK_LENGTH   16

struct mbedtls_cipher_context_t {
    /** Information about the associated cipher. */
    const struct mbedtls_cipher_info_t *MBEDTLS_PRIVATE(cipher_info);

    /** Key length to use. */
    int MBEDTLS_PRIVATE(key_bitlen);

    /** Operation that the key of the context has been
     * initialized for.
     */
    enum mbedtls_operation_t MBEDTLS_PRIVATE(operation);

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    /** Padding functions to use, if relevant for
     * the specific cipher mode.
     */
    void(*MBEDTLS_PRIVATE(add_padding))(unsigned char *output, size_t olen, size_t data_len);
    int(*MBEDTLS_PRIVATE(get_padding))(unsigned char *input, size_t ilen, size_t *data_len);
#endif

    /** Buffer for input that has not been processed yet. */
    unsigned char MBEDTLS_PRIVATE(unprocessed_data)[MBEDTLS_MAX_BLOCK_LENGTH];

    /** Number of Bytes that have not been processed yet. */
    size_t MBEDTLS_PRIVATE(unprocessed_len);

    /** Current IV or NONCE_COUNTER for CTR-mode, data unit (or sector) number
     * for XTS-mode. */
    unsigned char MBEDTLS_PRIVATE(iv)[MBEDTLS_MAX_IV_LENGTH];

    /** IV size in Bytes, for ciphers with variable-length IVs. */
    size_t MBEDTLS_PRIVATE(iv_size);

    /** The cipher-specific context. */
    void *MBEDTLS_PRIVATE(cipher_ctx);

#if defined(MBEDTLS_CMAC_C)
    /** CMAC-specific context. */
    struct mbedtls_cmac_context_t *MBEDTLS_PRIVATE(cmac_ctx);
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    /** Indicates whether the cipher operations should be performed
     *  by Mbed TLS' own crypto library or an external implementation
     *  of the PSA Crypto API.
     *  This is unset if the cipher context was established through
     *  mbedtls_cipher_setup(), and set if it was established through
     *  mbedtls_cipher_setup_psa().
     */
    unsigned char MBEDTLS_PRIVATE(psa_enabled);
#endif /* MBEDTLS_USE_PSA_CRYPTO && !MBEDTLS_DEPRECATED_REMOVED */

};

struct mbedtls_ccm_context {
    unsigned char MBEDTLS_PRIVATE(y)[16];    /*!< The Y working buffer */
    unsigned char MBEDTLS_PRIVATE(ctr)[16];  /*!< The counter buffer */
    size_t MBEDTLS_PRIVATE(plaintext_len);   /*!< Total plaintext length */
    size_t MBEDTLS_PRIVATE(add_len);         /*!< Total authentication data length */
    size_t MBEDTLS_PRIVATE(tag_len);         /*!< Total tag length */
    size_t MBEDTLS_PRIVATE(processed);       /*!< Track how many bytes of input data
                                                  were processed (chunked input).
                                                  Used independently for both auth data
                                                  and plaintext/ciphertext.
                                                  This variable is set to zero after
                                                  auth data input is finished. */
    unsigned int MBEDTLS_PRIVATE(q);         /*!< The Q working value */
    unsigned int MBEDTLS_PRIVATE(mode);      /*!< The operation to perform:
                                              #MBEDTLS_CCM_ENCRYPT or
                                              #MBEDTLS_CCM_DECRYPT or
                                              #MBEDTLS_CCM_STAR_ENCRYPT or
                                              #MBEDTLS_CCM_STAR_DECRYPT. */
#if defined(MBEDTLS_BLOCK_CIPHER_C)
    struct mbedtls_block_cipher_context_t MBEDTLS_PRIVATE(block_cipher_ctx);    /*!< The cipher context used. */
#else
    struct mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher_ctx);    /*!< The cipher context used. */
#endif
    int MBEDTLS_PRIVATE(state);              /*!< Working value holding context's
                                                  state. Used for chunked data input */
};

#if defined(MBEDTLS_GCM_LARGE_TABLE)
#define MBEDTLS_GCM_HTABLE_SIZE 256
#else
#define MBEDTLS_GCM_HTABLE_SIZE 16
#endif

struct mbedtls_gcm_context {
#if defined(MBEDTLS_BLOCK_CIPHER_C)
    struct mbedtls_block_cipher_context_t MBEDTLS_PRIVATE(block_cipher_ctx);  /*!< The cipher context used. */
#else
    struct mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher_ctx);    /*!< The cipher context used. */
#endif
    uint64_t MBEDTLS_PRIVATE(H)[MBEDTLS_GCM_HTABLE_SIZE][2]; /*!< Precalculated HTable. */
    uint64_t MBEDTLS_PRIVATE(len);                           /*!< The total length of the encrypted data. */
    uint64_t MBEDTLS_PRIVATE(add_len);                       /*!< The total length of the additional data. */
    unsigned char MBEDTLS_PRIVATE(base_ectr)[16];            /*!< The first ECTR for tag. */
    unsigned char MBEDTLS_PRIVATE(y)[16];                    /*!< The Y working value. */
    unsigned char MBEDTLS_PRIVATE(buf)[16];                  /*!< The buf working value. */
    unsigned char MBEDTLS_PRIVATE(mode);                     /*!< The operation to perform:
                                                              #MBEDTLS_GCM_ENCRYPT or
                                                              #MBEDTLS_GCM_DECRYPT. */
    unsigned char MBEDTLS_PRIVATE(acceleration);             /*!< The acceleration to use. */
};

#ifdef __cplusplus
}
#endif

#endif /* mode_contexts.h */
