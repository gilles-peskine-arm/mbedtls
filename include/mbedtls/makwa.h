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
                               unsigned work_factor,
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
                              unsigned work_factor,
                              int pre_hash, int post_hash,
                              const unsigned char *input, size_t input_length,
                              const unsigned char *salt, size_t salt_length,
                              const unsigned char *expected_output,
                              size_t output_size );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MAKWA_H */
