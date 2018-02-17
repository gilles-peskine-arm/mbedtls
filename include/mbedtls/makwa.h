 /**
 * \file makwa.h
 *
 * \brief The Makwa password hashing algorithm.
 *
 * Reference: Thomas Pornin. The Makwa Password Hashing Function. Feb 22, 2014.
 *
 * General considerations {#general}
 * ======================
 *
 * ## The modulus parameter {#modulus}
 *
 * This must be a Blum integer, i.e. the product of two primes p and q
 * such that p = q = 3 (mod 4). It must be larger than 2^1272.
 *
 * This value can be reused across many passwords and even across different
 * systems, but the factors p and q must not be shared  with any untrusted
 * entity.
 *
 * ## The work factor parameter {#workfactor}
 *
 * A hardness factor. The run time of the hashing is roughly proportional
 * to this value.
 *
 * ## The salt {#salt}
 *
 * To protect against systematic attacks, a salt value must not be reused.
 * Generate a new, random value each time you generate a password hash.
 *
 */
/*
 *  Copyright (C) 2018, Arm Limited, All Rights Reserved
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
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_MAKWA_H
#define MBEDTLS_MAKWA_H

#include <stddef.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "bignum.h"
#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_GENPRIME)
/**
 * \brief               Generate a modulus parameter for Makwa
 *                      and return its factors.
 *
 * See [General considerations](#modulus).
 *
 * The factors are not necessary for basic Makwa operation, only for the
 * fast path and escrow features. Leaking the factors considerably
 * weakens the security of the password hash, therefore you should use
 * mbedtls_makwa_generate_modulus() unless you need these features.
 *
 * \param n_bits        Bit size of the generated modulus. This must be
 *                      an even number.
 * \param n             On success, contains the generated modulus
 *                      n = p &times; q.
 * \param p             On success, contains the prime \c p.
 * \param q             On success, contains the prime \c q.
 * \param f_rng         RNG function
 * \param p_rng         RNG parameter
 *
 * \retval 0            Success
 * \retval MBEDTLS_ERR_MPI_BAD_INPUT_DATA
 *                      Invalid parameter.
 * \retval MBEDTLS_ERR_XXX
 *                      Error from the bignum module,
 *                      or error returned by \c f_rng.
 */
int mbedtls_makwa_generate_modulus_with_factors(
    size_t n_bits,
    mbedtls_mpi *n,
    mbedtls_mpi *p, mbedtls_mpi *q,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng );

/**
 * \brief               Generate a modulus parameter for Makwa.
 *
 * See [General considerations](#modulus).
 *
 * The factors are not necessary for basic Makwa operation, only for the
 * fast path and escrow features. Leaking the factors considerably
 * weakens the security of the password hash, therefore you should use
 * mbedtls_makwa_generate_modulus() unless you need these features.
 *
 * \param n_bits        Bit size of the generated modulus. This must be
 *                      an even number.
 * \param n             On success, contains the generated modulus.
 * \param f_rng         RNG function
 * \param p_rng         RNG parameter
 *
 * \retval 0            Success
 * \retval MBEDTLS_ERR_MPI_BAD_INPUT_DATA
 *                      Invalid parameter.
 * \retval MBEDTLS_ERR_XXX
 *                      Error from the bignum module,
 *                      or error returned by \c f_rng.
 */
int mbedtls_makwa_generate_modulus(
    size_t n_bits,
    mbedtls_mpi *n,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng );

#endif /* MBEDTLS_GENPRIME */

/** Integral type used to represent the work factor. */
typedef unsigned mbedtls_makwa_work_factor_t;

/**
 * \brief               Calculate the raw binary output of the Makwa password
 *                      hashing function.
 *
 * \note                To compare the output with some reference output,
 *                      call mbedtls_makwa_verify_raw() instead.
 *
 * \param md_alg        Hash algorithm to use for the calculation.
 * \param n             Modulus for the calculation.
 *                      See [General considerations](#modulus).
 * \param work_factor   Work factor (w).
 *                      See [General considerations](#workfactor).
 * \param pre_hash      1 to perform the optional pre-hashing step.
 *                      0 to not perform pre-hashing.
 * \param post_hash     1 to perform the optional post-hashing step.
 *                      0 to not perform post-hashing.
 * \param input         The password to hash. Without pre-hashing, this must
 *                      be at most 255 bytes long, and also at most k bytes
 *                      long if n < 2^{8k}.
 * \param input_length  Length of \c input in bytes.
 * \param salt          The salt for the calculation.
 *                      See [General considerations](#salt).
 * \param salt_length   Length of \c salt in bytes.
 * \param output        Output buffer. On success, this contains the Makwa
 *                      hash of the input and salt for the given parameters.
 * \param output_size   Size of \c output in bytes. Without
 *                      post-hashing, this must be exactly the byte length
 *                      of \c n. With post-hashing, this can be any size.
 *
 * \retval 0            Success.
 * \retval MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE
 *                      \c md_alg is not a supported hash function.
 * \retval MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      One of the parameters is invalid.
 * \retval MBEDTLS_ERR_MD_ALLOC_FAILED
 *                      There was insufficient memory for the calculation.
 * \retval MBEDTLS_ERR_XXX
 *                      Any error from the underlying hash function or
 *                      from the bignum module (\c MBEDTLS_ERR_MPI_XXX).
 */
int mbedtls_makwa_compute_raw( mbedtls_md_type_t md_alg,
                               const mbedtls_mpi *n,
                               mbedtls_makwa_work_factor_t work_factor,
                               int pre_hash, int post_hash,
                               const unsigned char *input, size_t input_length,
                               const unsigned char *salt, size_t salt_length,
                               unsigned char *output, size_t output_size );

/**
 * \brief               Compare a Makwa password hash with a reference value.
 *
 * \param md_alg        Hash algorithm to use for the calculation.
 * \param n             Modulus for the calculation.
 *                      See [General considerations](#modulus).
 * \param work_factor   Work factor (w).
 *                      See [General considerations](#workfactor).
 * \param pre_hash      1 to perform the optional pre-hashing step.
 *                      0 to not perform pre-hashing.
 * \param post_hash     1 to perform the optional post-hashing step.
 *                      0 to not perform post-hashing.
 * \param input         The password to hash. Without pre-hashing, this must
 *                      be at most 255 bytes long, and also at most k bytes
 *                      long if n < 2^{8k}.
 * \param input_length  Length of \c input in bytes.
 * \param salt          The salt for the calculation.
 *                      See [General considerations](#salt).
 * \param salt_length   Length of \c salt in bytes.
 * \param expected_output  The expected output from the calculation.
 * \param output_size   Size of \c expected_output in bytes. Without
 *                      post-hashing, this must be exactly the byte length
 *                      of \c n. With post-hashing, this can be any size.
 *
 * \retval 0            The expected output is identical to the calculated
 *                      output. This means that the password matches.
 * \retval MBEDTLS_ERR_MD_VERIFY_FAILED
 *                      The expected output differs from the calculated output.
 *                      This means that the password does not match.
 * \retval MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE
 *                      \c md_alg is not a supported hash function.
 * \retval MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      One of the parameters is invalid.
 * \retval MBEDTLS_ERR_MD_ALLOC_FAILED
 *                      There was insufficient memory for the calculation.
 * \retval MBEDTLS_ERR_XXX
 *                      Any error from the underlying hash function or
 *                      from the bignum module (\c MBEDTLS_ERR_MPI_XXX).
 */
int mbedtls_makwa_verify_raw( mbedtls_md_type_t md_alg,
                              const mbedtls_mpi *n,
                              mbedtls_makwa_work_factor_t work_factor,
                              int pre_hash, int post_hash,
                              const unsigned char *input, size_t input_length,
                              const unsigned char *salt, size_t salt_length,
                              const unsigned char *expected_output,
                              size_t output_size );

#if defined(MBEDTLS_BASE64_C)

/**
 * \brief               Calculate the Makwa hash of a password and output
 *                      it in text format.
 *
 * \note                To check a password against a known hash,
 *                      call mbedtls_makwa_verify_base64() instead.
 *
 * \param md_alg        Hash algorithm to use for the calculation.
 * \param n             Modulus for the calculation.
 *                      See [General considerations](#modulus).
 * \param work_factor   Work factor (w).
 *                      See [General considerations](#workfactor).
 * \param pre_hash      1 to perform the optional pre-hashing step.
 *                      0 to not perform pre-hashing.
 * \param post_hash     1 to perform the optional post-hashing step.
 *                      0 to not perform post-hashing.
 * \param input         The password to hash. Without pre-hashing, this must
 *                      be at most 255 bytes long, and also at most k bytes
 *                      long if n < 2^{8k}.
 * \param input_length  Length of \c input in bytes.
 * \param salt          The salt for the calculation.
 *                      See [General considerations](#salt).
 * \param salt_length   Length of \c salt in bytes.
 * \param raw_output_length  Number of bytes to use as a checksum.
 *                      Without post-hashing, this must be exactly the byte
 *                      length of \c n. With post-hashing, this can be any
 *                      size that is at least 10.
 * \param output        Output buffer. On success, this contains the Makwa
 *                      output formatted in the standard Base64 format
 *                      (`B64(H_8(N))+"_"+F+"_"+B64(salt)+"+"+B64(input)`).
 * \param output_buffer_size  Size of \c output in bytes. This must be at least
 *                      4 / 3 &times; \c raw_output_length, rounded up.
 *
 * \retval 0            Success.
 * \retval MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
 *                      \c output_size is too small.
 * \retval MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE
 *                      \c md_alg is not a supported hash function.
 * \retval MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      One of the parameters is invalid.
 * \retval MBEDTLS_ERR_MD_ALLOC_FAILED
 *                      There was insufficient memory for the calculation.
 * \retval MBEDTLS_ERR_XXX
 *                      Any error from the underlying hash function or
 *                      from the bignum module (\c MBEDTLS_ERR_MPI_XXX).
 */
int mbedtls_makwa_compute_base64( mbedtls_md_type_t md_alg,
                                  const mbedtls_mpi *n,
                                  mbedtls_makwa_work_factor_t work_factor,
                                  int pre_hash, int post_hash,
                                  const unsigned char *input,
                                  size_t input_length,
                                  const unsigned char *salt,
                                  size_t salt_length,
                                  size_t raw_output_length,
                                  char *output,
                                  size_t output_buffer_size );

/**
 * \brief               Calculate the Makwa hash of a password and output
 *                      it in text format.
 *
 * \note                To check a password against a known hash,
 *                      call mbedtls_makwa_verify_base64() instead.
 *
 * \param md_alg        Hash algorithm to use for the calculation.
 * \param n             Modulus for the calculation.
 *                      See [General considerations](#modulus).
 * \param work_factor   Work factor (w).
 *                      See [General considerations](#workfactor).
 *                      This must be either 2*2^d or 3*2^d for some integer d.
 * \param pre_hash      1 to perform the optional pre-hashing step.
 *                      0 to not perform pre-hashing.
 * \param post_hash     1 to perform the optional post-hashing step.
 *                      0 to not perform post-hashing.
 * \param input         The password to hash. Without pre-hashing, this must
 *                      be at most 255 bytes long, and also at most k bytes
 *                      long if n < 2^{8k}.
 * \param input_length  Length of \c input in bytes.
 * \param salt          The salt for the calculation.
 *                      See [General considerations](#salt).
 * \param salt_length   Length of \c salt in bytes.
 * \param raw_output_length  Number of bytes to use as a checksum.
 *                      Without post-hashing, this must be exactly the byte
 *                      length of \c n. With post-hashing, this can be any
 *                      size that is at least 10.
 * \param output        Output buffer. On success, this contains the Makwa
 *                      output formatted in the standard Base64 format
 *                      (`B64(H_8(N))+"_"+F+"_"+B64(salt)+"+"+B64(input)`),
 *                      with a terminating null byte.
 * \param output_size   Size of \c output in bytes. This must be at least
 *                      1 + 4 / 3 \times \c raw_output_length, rounded up.
 *
 * \retval 0            Success.
 * \retval MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
 *                      \c output_size is too small.
 * \retval MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE
 *                      \c md_alg is not a supported hash function.
 * \retval MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      One of the parameters is invalid.
 * \retval MBEDTLS_ERR_MD_ALLOC_FAILED
 *                      There was insufficient memory for the calculation.
 * \retval MBEDTLS_ERR_XXX
 *                      Any error from the underlying hash function or
 *                      from the bignum module (\c MBEDTLS_ERR_MPI_XXX).
 */
int mbedtls_makwa_compute_base64( mbedtls_md_type_t md_alg,
                                  const mbedtls_mpi *n,
                                  mbedtls_makwa_work_factor_t work_factor,
                                  int pre_hash, int post_hash,
                                  const unsigned char *input,
                                  size_t input_length,
                                  const unsigned char *salt,
                                  size_t salt_length,
                                  size_t raw_output_length,
                                  char *output,
                                  size_t output_buffer_size );
/**
 * \brief               Verify a password against a reference hash
 *                      in text format.
 *
 * \param md_alg        Hash algorithm to use for the calculation.
 * \param n             Modulus for the calculation.
 *                      See [General considerations](#modulus).
 *                      This value must be equal to the one that was
 *                      used to generate the hash.
 * \param input         The password to hash. Without pre-hashing, this must
 *                      be at most 255 bytes long, and also at most k bytes
 *                      long if n < 2^{8k}.
 * \param input_length  Length of \c input in bytes.
 * \param expected_output
 *                      The reference hash to check against, in the
 *                      standard Makwa text format, as a null-terminated
 *                      string. This value encodes the salt, the work factor,
 *                      and whether pre- and post-hashing are used. The value
 *                      also encodes a checksum for \c n, but not \c n itself.
 *
 * \retval 0            The expected output is identical to the calculated
 *                      output. This means that the password matches.
 * \retval MBEDTLS_ERR_MD_VERIFY_FAILED
 *                      The expected output differs from the calculated output.
 *                      This means that the password does not match.
 * \retval MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE
 *                      \c md_alg is not a supported hash function,
 *                      or the work factor encoded in expected_output is
 *                      too large to fit in unsigned int on this platform.
 * \retval MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      Either \c n is invalid or \c expected_output does
 *                      not have the expected format.
 * \retval MBEDTLS_ERR_MD_ALLOC_FAILED
 *                      There was insufficient memory for the calculation.
 * \retval MBEDTLS_ERR_XXX
 *                      Any error from the underlying hash function or
 *                      from the bignum module (\c MBEDTLS_ERR_MPI_XXX).
 */
int mbedtls_makwa_verify_base64( mbedtls_md_type_t md_alg,
                                 const mbedtls_mpi *n,
                                 const unsigned char *input,
                                 size_t input_length,
                                 const char *expected_output );

#endif /* MBEDTLS_BASE64_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MAKWA_H */
