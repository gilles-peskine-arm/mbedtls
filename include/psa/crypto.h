/**
 * \file psa/crypto.h
 * \brief Platform Security Architecture cryptography module
 */

#ifndef PSA_CRYPTO_H
#define PSA_CRYPTO_H

#include "crypto_platform.h"

#include <stddef.h>

#ifdef __DOXYGEN_ONLY__
/* This __DOXYGEN_ONLY__ block contains mock definitions for things that
 * must be defined in the crypto_platform.h header. These mock definitions
 * are present in this file as a convenience to generate pretty-printed
 * documentation that includes those definitions. */

/** \defgroup platform Implementation-specific definitions
 * @{
 */

/** \brief Key slot number.
 *
 * This type represents key slots. It must be an unsigned integral
 * type. The choice of type is implementation-dependent.
 * 0 is not a valid key slot number. The meaning of other values is
 * implementation dependent.
 *
 * At any given point in time, each key slot either contains a
 * cryptographic object, or is empty. Key slots are persistent:
 * once set, the cryptographic object remains in the key slot until
 * explicitly destroyed.
 */
typedef _unsigned_integral_type_ psa_key_slot_t;

/**@}*/
#endif /* __DOXYGEN_ONLY__ */

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup basic Basic definitions
 * @{
 */

/**
 * \brief Function return status.
 *
 * Zero indicates success, anything else indicates an error.
 */
typedef enum {
    /** The action was completed successfully. */
    PSA_SUCCESS = 0,
    /** The requested operation or a parameter is not supported
        by this implementation. */
    PSA_ERROR_NOT_SUPPORTED,
    /** The requested action is denied by a policy. */
    PSA_ERROR_NOT_PERMITTED,
    /** An output buffer is too small. */
    PSA_ERROR_BUFFER_TOO_SMALL,
    /** A slot is occupied, but must be empty to carry out the
        requested action. */
    PSA_ERROR_OCCUPIED_SLOT,
    /** A slot is empty, but must be occupied to carry out the
        requested action. */
    PSA_ERROR_EMPTY_SLOT,
    /** The requested action cannot be performed in the current state. */
    PSA_ERROR_BAD_STATE,
    /** The parameters passed to the function are invalid. */
    PSA_ERROR_INVALID_ARGUMENT,
    /** There is not enough runtime memory. */
    PSA_ERROR_INSUFFICIENT_MEMORY,
    /** There is not enough persistent storage. */
    PSA_ERROR_INSUFFICIENT_STORAGE,
    /** There was a communication failure inside the implementation. */
    PSA_ERROR_COMMUNICATION_FAILURE,
    /** There was a storage failure that may have led to data loss. */
    PSA_ERROR_STORAGE_FAILURE,
    /** A hardware failure was detected. */
    PSA_ERROR_HARDWARE_FAILURE,
    /** A tampering attempt was detected. */
    PSA_ERROR_TAMPERING_DETECTED,
    /** There is not enough entropy to generate random data needed
        for the requested action. */
    PSA_ERROR_INSUFFICIENT_ENTROPY,
    /** The signature, MAC or hash is incorrect. */
    PSA_ERROR_INVALID_SIGNATURE,
    /** The decrypted padding is incorrect. */
    PSA_ERROR_INVALID_PADDING,
    /** An error occurred that does not correspond to any defined
        failure cause. */
    PSA_ERROR_UNKNOWN_ERROR,
} psa_status_t;

/**
 * \brief Library initialization.
 *
 * Applications must call this function before calling any other
 * function in this module.
 *
 * Applications may call this function more than once. Once a call
 * succeeds, subsequent calls are guaranteed to succeed.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 * \retval PSA_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_crypto_init(void);

/**@}*/

/** \defgroup crypto_types Key and algorithm types
 * @{
 */

/** \brief Encoding of a key type.
 */
typedef uint32_t psa_key_type_t;

/** An invalid key type value.
 *
 * Zero is not the encoding of any key type.
 */
#define PSA_KEY_TYPE_NONE                       ((psa_key_type_t)0x00000000)

/** Vendor-defined flag
 *
 * Key types defined by this standard will never have the
 * #PSA_KEY_TYPE_VENDOR_FLAG bit set. Vendors who define additional key types
 * must use an encoding with the #PSA_KEY_TYPE_VENDOR_FLAG bit set and should
 * respect the bitwise structure used by standard encodings whenever practical.
 */
#define PSA_KEY_TYPE_VENDOR_FLAG                ((psa_key_type_t)0x80000000)

#define PSA_KEY_TYPE_CATEGORY_MASK              ((psa_key_type_t)0x7e000000)
#define PSA_KEY_TYPE_RAW_DATA                   ((psa_key_type_t)0x02000000)
#define PSA_KEY_TYPE_CATEGORY_SYMMETRIC         ((psa_key_type_t)0x04000000)
#define PSA_KEY_TYPE_CATEGORY_ASYMMETRIC        ((psa_key_type_t)0x06000000)
#define PSA_KEY_TYPE_PAIR_FLAG                  ((psa_key_type_t)0x01000000)

#define PSA_KEY_TYPE_IS_VENDOR_DEFINED(type) \
    (((type) & PSA_KEY_TYPE_VENDOR_FLAG) != 0)
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type)                                \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_ASYMMETRIC)
#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type)                                \
    (((type) & (PSA_KEY_TYPE_CATEGORY_MASK | PSA_KEY_TYPE_PAIR_FLAG) == \
      PSA_KEY_TYPE_CATEGORY_ASYMMETRIC))
#define PSA_KEY_TYPE_IS_KEYPAIR(type)                                   \
    (((type) & (PSA_KEY_TYPE_CATEGORY_MASK | PSA_KEY_TYPE_PAIR_FLAG)) == \
     (PSA_KEY_TYPE_CATEGORY_ASYMMETRIC | PSA_KEY_TYPE_PAIR_FLAG))

/** \brief Encoding of a cryptographic algorithm.
 *
 * For algorithms that can be applied to multiple key types, this type
 * does not encode the key type. For example, for symmetric ciphers
 * based on a block cipher, #psa_algorithm_t encodes the block cipher
 * mode and the padding mode while the block cipher itself is encoded
 * via #psa_key_type_t.
 */
typedef uint32_t psa_algorithm_t;

#define PSA_ALG_VENDOR_FLAG                     ((psa_algorithm_t)0x80000000)
#define PSA_ALG_CATEGORY_MASK                   ((psa_algorithm_t)0x7f000000)
#define PSA_ALG_CATEGORY_HASH                   ((psa_algorithm_t)0x01000000)
#define PSA_ALG_CATEGORY_MAC                    ((psa_algorithm_t)0x02000000)
#define PSA_ALG_CATEGORY_CIPHER                 ((psa_algorithm_t)0x04000000)
#define PSA_ALG_CATEGORY_AEAD                   ((psa_algorithm_t)0x06000000)
#define PSA_ALG_CATEGORY_SIGN                   ((psa_algorithm_t)0x10000000)
#define PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION  ((psa_algorithm_t)0x12000000)
#define PSA_ALG_CATEGORY_KEY_AGREEMENT          ((psa_algorithm_t)0x22000000)
#define PSA_ALG_CATEGORY_KEY_DERIVATION         ((psa_algorithm_t)0x30000000)

#define PSA_ALG_IS_VENDOR_DEFINED(alg)                                  \
    (((alg) & PSA_ALG_VENDOR_FLAG) != 0)
/** Whether the specified algorithm is a hash algorithm.
 *
 * \param alg An algorithm identifier (\c PSA_ALG_XXX value)
 *
 * \return 1 if \c alg is a hash algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a valid
 *         algorithm identifier. */
#define PSA_ALG_IS_HASH(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_HASH)
#define PSA_ALG_IS_MAC(alg)                                             \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_MAC)
#define PSA_ALG_IS_CIPHER(alg)                                          \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_CIPHER)
#define PSA_ALG_IS_AEAD(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_AEAD)
#define PSA_ALG_IS_SIGN(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_SIGN)
#define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg)                           \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION)
#define PSA_ALG_IS_KEY_AGREEMENT(alg)                                   \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_KEY_AGREEMENT)
#define PSA_ALG_IS_KEY_DERIVATION(alg)                                  \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_KEY_DERIVATION)

/**@}*/

/** \defgroup key_management Key management
 * @{
 */

/**
 * \brief Import a key in binary format.
 *
 * This function supports any output from psa_export_key(). Refer to the
 * documentation of psa_export_key() for the format for each key type.
 *
 * \param key         Slot where the key will be stored. This must be a
 *                    valid slot for a key of the chosen type. It must
 *                    be unoccupied.
 * \param type        Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param data        Buffer containing the key data.
 * \param data_length Size of the \c data buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         The key type or key size is not supported.
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the key data is not correctly formatted.
 * \retval PSA_ERROR_OCCUPIED_SLOT
           There is already a key in the specified slot.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_import_key(psa_key_slot_t key,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length);

/**
 * \brief Destroy a key.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_destroy_key(psa_key_slot_t key);

/**
 * \brief Get basic metadata about a key.
 *
 * \param key           Slot whose content is queried. This must
 *                      be an occupied key slot.
 * \param type          On success, the key type (a \c PSA_KEY_TYPE_XXX value).
 *                      This may be a null pointer, in which case the key type
 *                      is not written.
 * \param bits          On success, the key size in bits.
 *                      This may be a null pointer, in which case the key size
 *                      is not written.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_get_key_information(psa_key_slot_t key,
                                     psa_key_type_t *type,
                                     size_t *bits);

/**
 * \brief Export a key in binary format.
 *
 * The output of this function can be passed to psa_import_key() to
 * create an equivalent object.
 *
 * If a key is created with psa_import_key() and then exported with
 * this function, it is not guaranteed that the resulting data is
 * identical: the implementation may choose a different representation
 * of the same key if the format permits it.
 *
 * For standard key types, the output format is as follows:
 *
 * - For symmetric keys (including MAC keys), the format is the
 *   raw bytes of the key.
 * - For DES, the key data consists of 8 bytes. The parity bits must be
 *   correct.
 * - For Triple-DES, the format is the concatenation of the
 *   two or three DES keys.
 * - For RSA key pairs (#PSA_KEY_TYPE_RSA_KEYPAIR), the format
 *   is the non-encrypted DER representation defined by PKCS\#8 (RFC 5208)
 *   as PrivateKeyInfo.
 * - For RSA public keys (#PSA_KEY_TYPE_RSA_PUBLIC_KEY), the format
 *   is the DER representation defined by X.509.
 *
 * \param key           Slot whose content is to be exported. This must
 *                      be an occupied key slot.
 * \param data          Buffer where the key data is to be written.
 * \param data_size     Size of the \c data buffer in bytes.
 * \param data_length   On success, the number of bytes
 *                      that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_export_key(psa_key_slot_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length);

/**
 * \brief Export a public key or the public part of a key pair in binary format.
 *
 * The output of this function can be passed to psa_import_key() to
 * create an object that is equivalent to the public key.
 *
 * For standard key types, the output format is as follows:
 *
 * - For RSA keys (#PSA_KEY_TYPE_RSA_KEYPAIR or #PSA_KEY_TYPE_RSA_PUBLIC_KEY),
 *   the format is the DER representation defined by X.509.
 *
 * \param key           Slot whose content is to be exported. This must
 *                      be an occupied key slot.
 * \param data          Buffer where the key data is to be written.
 * \param data_size     Size of the \c data buffer in bytes.
 * \param data_length   On success, the number of bytes
 *                      that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_export_public_key(psa_key_slot_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length);

/**@}*/

/** \defgroup policy Key policies
 * @{
 */

/** \brief Encoding of permitted usage on a key. */
typedef uint32_t psa_key_usage_t;

#define PSA_KEY_USAGE_EXPORT                    ((psa_key_usage_t)0x00000001)

#define PSA_KEY_USAGE_ENCRYPT                   ((psa_key_usage_t)0x00000100)
#define PSA_KEY_USAGE_DECRYPT                   ((psa_key_usage_t)0x00000200)
#define PSA_KEY_USAGE_SIGN                      ((psa_key_usage_t)0x00000400)
#define PSA_KEY_USAGE_VERIFY                    ((psa_key_usage_t)0x00000800)

/** The type of the key policy data structure.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_key_policy_s psa_key_policy_t;

/** \brief Initialize a key policy structure to a default that forbids all
 * usage of the key. */
void psa_key_policy_init(psa_key_policy_t *policy);

void psa_key_policy_set_usage(psa_key_policy_t *policy,
                              psa_key_usage_t usage,
                              psa_algorithm_t alg);

psa_key_usage_t psa_key_policy_get_usage(psa_key_policy_t *policy);

psa_algorithm_t psa_key_policy_get_algorithm(psa_key_policy_t *policy);

/** \brief Set the usage policy on a key slot.
 *
 * This function must be called on an empty key slot, before importing,
 * generating or creating a key in the slot. Changing the policy of an
 * existing key is not permitted.
 */
psa_status_t psa_set_key_policy(psa_key_slot_t key,
                                const psa_key_policy_t *policy);

psa_status_t psa_get_key_policy(psa_key_slot_t key,
                                psa_key_policy_t *policy);

/**@}*/

/** \defgroup persistence Key lifetime
 * @{
 */

/** Encoding of key lifetimes.
 */
typedef uint32_t psa_key_lifetime_t;

/** A volatile key slot retains its content as long as the application is
 * running. It is guaranteed to be erased on a power reset.
 */
#define PSA_KEY_LIFETIME_VOLATILE               ((psa_key_lifetime_t)0x00000000)

/** A persistent key slot retains its content as long as it is not explicitly
 * destroyed.
 */
#define PSA_KEY_LIFETIME_PERSISTENT             ((psa_key_lifetime_t)0x00000001)

/** A write-once key slot may not be modified once a key has been set.
 * It will retain its content as long as the device remains operational.
 */
#define PSA_KEY_LIFETIME_WRITE_ONCE             ((psa_key_lifetime_t)0x7fffffff)

/** \brief Retrieve the lifetime of a key slot.
 *
 * The assignment of lifetimes to slots is implementation-dependent.
 */
psa_status_t psa_get_key_lifetime(psa_key_slot_t key,
                                  psa_key_lifetime_t *lifetime);

/** \brief Change the lifetime of a key slot.
 *
 * Whether the lifetime of a key slot can be changed at all, and if so
 * whether the lifetime of an occupied key slot can be changed, is
 * implementation-dependent.
 */
psa_status_t psa_set_key_lifetime(psa_key_slot_t key,
                                  const psa_key_lifetime_t *lifetime);

/**@}*/

#ifdef __cplusplus
}
#endif

/* The file "crypto_struct.h" contains definitions for
 * implementation-specific structs that are declared above. */
#include "crypto_struct.h"

/* The file "crypto_extra.h" contains vendor-specific definitions. This
 * can include vendor-defined algorithms, extra functions, etc. */
#include "crypto_extra.h"

#endif /* PSA_CRYPTO_H */
