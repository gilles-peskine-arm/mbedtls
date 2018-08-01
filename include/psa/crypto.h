/**
 * \file psa/crypto.h
 * \brief Platform Security Architecture cryptography module
 */
/*
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#if defined(PSA_SUCCESS)
/* If PSA_SUCCESS is defined, assume that PSA crypto is being used
 * together with PSA IPC, which also defines the identifier
 * PSA_SUCCESS. We must not define PSA_SUCCESS ourselves in that case;
 * the other error code names don't clash. Also define psa_status_t as
 * an alias for the type used by PSA IPC. This is a temporary hack
 * until we unify error reporting in PSA IPC and PSA crypto.
 *
 * Note that psa_defs.h must be included before this header!
 */
typedef psa_error_t psa_status_t;

#else /* defined(PSA_SUCCESS) */

/**
 * \brief Function return status.
 *
 * This is either #PSA_SUCCESS (which is zero), indicating success,
 * or a nonzero value indicating that an error occurred. Errors are
 * encoded as one of the \c PSA_ERROR_xxx values defined here.
 */
typedef int32_t psa_status_t;

/** The action was completed successfully. */
#define PSA_SUCCESS ((psa_status_t)0)

#endif /* !defined(PSA_SUCCESS) */

/** An error occurred that does not correspond to any defined
 * failure cause.
 *
 * Implementations may use this error code if none of the other standard
 * error codes are applicable. */
#define PSA_ERROR_UNKNOWN_ERROR         ((psa_status_t)1)

/** The requested operation or a parameter is not supported
 * by this implementation.
 *
 * Implementations should return this error code when an enumeration
 * parameter such as a key type, algorithm, etc. is not recognized.
 * If a combination of parameters is recognized and identified as
 * not valid, return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t)2)

/** The requested action is denied by a policy.
 *
 * Implementations should return this error code when the parameters
 * are recognized as valid and supported, and a policy explicitly
 * denies the requested operation.
 *
 * If a subset of the parameters of a function call identify a
 * forbidden operation, and another subset of the parameters are
 * not valid or not supported, it is unspecified whether the function
 * returns #PSA_ERROR_NOT_PERMITTED, #PSA_ERROR_NOT_SUPPORTED or
 * #PSA_ERROR_INVALID_ARGUMENT. */
#define PSA_ERROR_NOT_PERMITTED         ((psa_status_t)3)

/** An output buffer is too small.
 *
 * Applications can call the `PSA_xxx_SIZE` macro listed in the function
 * description to determine a sufficient buffer size.
 *
 * Implementations should preferably return this error code only
 * in cases when performing the operation with a larger output
 * buffer would succeed. However implementations may return this
 * error if a function has invalid or unsupported parameters in addition
 * to the parameters that determine the necessary output buffer size. */
#define PSA_ERROR_BUFFER_TOO_SMALL      ((psa_status_t)4)

/** A slot is occupied, but must be empty to carry out the
 * requested action.
 *
 * If the slot number is invalid (i.e. the requested action could
 * not be performed even after erasing the slot's content),
 * implementations shall return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_OCCUPIED_SLOT         ((psa_status_t)5)

/** A slot is empty, but must be occupied to carry out the
 * requested action.
 *
 * If the slot number is invalid (i.e. the requested action could
 * not be performed even after creating appropriate content in the slot),
 * implementations shall return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_EMPTY_SLOT            ((psa_status_t)6)

/** The requested action cannot be performed in the current state.
 *
 * Multipart operations return this error when one of the
 * functions is called out of sequence. Refer to the function
 * descriptions for permitted sequencing of functions.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_OCCUPIED_SLOT or #PSA_ERROR_EMPTY_SLOT
 * as applicable. */
#define PSA_ERROR_BAD_STATE             ((psa_status_t)7)

/** The parameters passed to the function are invalid.
 *
 * Implementations may return this error any time a parameter or
 * combination of parameters are recognized as invalid.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_OCCUPIED_SLOT or #PSA_ERROR_EMPTY_SLOT
 * as applicable. */
#define PSA_ERROR_INVALID_ARGUMENT      ((psa_status_t)8)

/** There is not enough runtime memory.
 *
 * If the action is carried out across multiple security realms, this
 * error can refer to available memory in any of the security realms. */
#define PSA_ERROR_INSUFFICIENT_MEMORY   ((psa_status_t)9)

/** There is not enough persistent storage.
 *
 * Functions that modify the key storage return this error code if
 * there is insufficient storage space on the host media. In addition,
 * many functions that do not otherwise access storage may return this
 * error code if the implementation requires a mandatory log entry for
 * the requested action and the log storage space is full. */
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t)10)

/** There was a communication failure inside the implementation.
 *
 * This can indicate a communication failure between the application
 * and an external cryptoprocessor or between the cryptoprocessor and
 * an external volatile or persistent memory. A communication failure
 * may be transient or permanent depending on the cause.
 *
 * \warning If a function returns this error, it is undetermined
 * whether the requested action has completed or not. Implementations
 * should return #PSA_SUCCESS on successful completion whenver
 * possible, however functions may return #PSA_ERROR_COMMUNICATION_FAILURE
 * if the requested action was completed successfully in an external
 * cryptoprocessor but there was a breakdown of communication before
 * the cryptoprocessor could report the status to the application.
 */
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)11)

/** There was a storage failure that may have led to data loss.
 *
 * This error indicates that some persistent storage is corrupted.
 * It should not be used for a corruption of volatile memory
 * (use #PSA_ERROR_TAMPERING_DETECTED), for a communication error
 * between the cryptoprocessor and its external storage (use
 * #PSA_ERROR_COMMUNICATION_FAILURE), or when the storage is
 * in a valid state but is full (use #PSA_ERROR_INSUFFICIENT_STORAGE).
 *
 * Note that a storage failure does not indicate that any data that was
 * previously read is invalid. However this previously read data may no
 * longer be readable from storage.
 *
 * When a storage failure occurs, it is no longer possible to ensure
 * the global integrity of the keystore. Depending on the global
 * integrity guarantees offered by the implementation, access to other
 * data may or may not fail even if the data is still readable but
 * its integrity canont be guaranteed.
 *
 * Implementations should only use this error code to report a
 * permanent storage corruption. However application writers should
 * keep in mind that transient errors while reading the storage may be
 * reported using this error code. */
#define PSA_ERROR_STORAGE_FAILURE       ((psa_status_t)12)

/** A hardware failure was detected.
 *
 * A hardware failure may be transient or permanent depending on the
 * cause. */
#define PSA_ERROR_HARDWARE_FAILURE      ((psa_status_t)13)

/** A tampering attempt was detected.
 *
 * If an application receives this error code, there is no guarantee
 * that previously accessed or computed data was correct and remains
 * confidential. Applications should not perform any security function
 * and should enter a safe failure state.
 *
 * Implementations may return this error code if they detect an invalid
 * state that cannot happen during normal operation and that indicates
 * that the implementation's security guarantees no longer hold. Depending
 * on the implementation architecture and on its security and safety goals,
 * the implementation may forcibly terminate the application.
 *
 * This error code is intended as a last resort when a security breach
 * is detected and it is unsure whether the keystore data is still
 * protected. Implementations shall only return this error code
 * to report an alarm from a tampering detector, to indicate that
 * the confidentiality of stored data can no longer be guaranteed,
 * or to indicate that the integrity of previously returned data is now
 * considered compromised. Implementations shall not use this error code
 * to indicate a hardware failure that merely makes it impossible to
 * perform the requested operation (use #PSA_ERROR_COMMUNICATION_FAILURE,
 * #PSA_ERROR_STORAGE_FAILURE, #PSA_ERROR_HARDWARE_FAILURE,
 * #PSA_ERROR_INSUFFICIENT_ENTROPY or other applicable error code
 * instead).
 *
 * This error indicates an attack against the application. Implementations
 * shall not return this error code as a consequence of the behavior of
 * the application itself. */
#define PSA_ERROR_TAMPERING_DETECTED    ((psa_status_t)14)

/** There is not enough entropy to generate random data needed
 * for the requested action.
 *
 * This error indicates a failure of a hardware random generator.
 * Application writers should note that this error can be returned not
 * only by functions whose purpose is to generate random data, such
 * as key, IV or nonce generation, but also by functions that execute
 * an algorithm with a randomized result, as well as functions that
 * use randomization of intermediate computations as a countermeasure
 * to certain attacks.
 *
 * Implementations should avoid returning this error after psa_crypto_init()
 * has succeeded. Implementations should generate sufficient
 * entropy during initialization and subsequently use a cryptographically
 * secure pseudorandom generator (PRNG). However implementations may return
 * this error at any time if a policy requires the PRNG to be reseeded
 * during normal operation. */
#define PSA_ERROR_INSUFFICIENT_ENTROPY  ((psa_status_t)15)

/** The signature, MAC or hash is incorrect.
 *
 * Verification functions return this error if the verification
 * calculations completed successfully, and the value to be verified
 * was determined to be incorrect.
 *
 * If the value to verify has an invalid size, implementations may return
 * either #PSA_ERROR_INVALID_ARGUMENT or #PSA_ERROR_INVALID_SIGNATURE. */
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t)16)

/** The decrypted padding is incorrect.
 *
 * \warning In some protocols, when decrypting data, it is essential that
 * the behavior of the application does not depend on whether the padding
 * is correct, down to precise timing. Applications should prefer
 * protocols that use authenticated encryption rather than plain
 * encryption. If the application must perform a decryption of
 * unauthenticated data, the application writer should take care not
 * to reveal whether the padding is invalid.
 *
 * Implementations should strive to make valid and invalid padding
 * as close as possible to indistinguishable to an external observer.
 * In particular, the timing of a decryption operation should not
 * depend on the validity of the padding. */
#define PSA_ERROR_INVALID_PADDING       ((psa_status_t)17)

/** The generator has insufficient capacity left.
 *
 * Once a function returns this error, attempts to read from the
 * generator will always return this error. */
#define PSA_ERROR_INSUFFICIENT_CAPACITY ((psa_status_t)18)

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
/** Raw data.
 *
 * A "key" of this type cannot be used for any cryptographic operation.
 * Applications may use this type to store arbitrary data in the keystore. */
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
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is a hash algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a valid
 *         algorithm identifier.
 */
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
 *         The key type or key size is not supported, either by the
 *         implementation in general or in this particular slot.
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the key data is not correctly formatted.
 * \retval PSA_ERROR_OCCUPIED_SLOT
 *         There is already a key in the specified slot.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_import_key(psa_key_slot_t key,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length);

/**
 * \brief Destroy a key and restore the slot to its default state.
 *
 * This function destroys the content of the key slot from both volatile
 * memory and, if applicable, non-volatile storage. Implementations shall
 * make a best effort to ensure that any previous content of the slot is
 * unrecoverable.
 *
 * This function also erases any metadata such as policies. It returns the
 * specified slot to its default state.
 *
 * \param key           The key slot to erase.
 *
 * \retval PSA_SUCCESS
 *         The slot's content, if any, has been erased.
 * \retval PSA_ERROR_NOT_PERMITTED
 *         The slot holds content and cannot be erased because it is
 *         read-only, either due to a policy or due to physical restrictions.
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         The specified slot number does not designate a valid slot.
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 *         There was an failure in communication with the cryptoprocessor.
 *         The key material may still be present in the cryptoprocessor.
 * \retval PSA_ERROR_STORAGE_FAILURE
 *         The storage is corrupted. Implementations shall make a best effort
 *         to erase key material even in this stage, however applications
 *         should be aware that it may be impossible to guarantee that the
 *         key material is not recoverable in such cases.
 * \retval PSA_ERROR_TAMPERING_DETECTED
 *         An unexpected condition which is not a storage corruption or
 *         a communication failure occurred. The cryptoprocessor may have
 *         been compromised.
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

/** Whether the key may be exported.
 *
 * A public key or the public part of a key pair may always be exported
 * regardless of the value of this permission flag.
 *
 * If a key does not have export permission, implementations shall not
 * allow the key to be exported in plain form from the cryptoprocessor,
 * whether through psa_export_key() or through a proprietary interface.
 * The key may however be exportable in a wrapped form, i.e. in a form
 * where it is encrypted by another key.
 */
#define PSA_KEY_USAGE_EXPORT                    ((psa_key_usage_t)0x00000001)

/** Whether the key may be used to encrypt a message.
 *
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_ENCRYPT                   ((psa_key_usage_t)0x00000100)

/** Whether the key may be used to decrypt a message.
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_DECRYPT                   ((psa_key_usage_t)0x00000200)

/** Whether the key may be used to sign a message.
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_SIGN                      ((psa_key_usage_t)0x00000400)

/** Whether the key may be used to verify a message signature.
 *
 * For a key pair, this concerns the public key.
 */
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

/** \brief Set the standard fields of a policy structure.
 *
 * Note that this function does not make any consistency check of the
 * parameters. The values are only checked when applying the policy to
 * a key slot with psa_set_key_policy().
 */
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
 *
 * Implementations may set restrictions on supported key policies
 * depending on the key type and the key slot.
 */
psa_status_t psa_set_key_policy(psa_key_slot_t key,
                                const psa_key_policy_t *policy);

/** \brief Get the usage policy for a key slot.
 */
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
