/**
 *  Core bignum functions
 *
 *  This interface should only be used by the legacy bignum module (bignum.h)
 *  and the modular bignum modules (bignum_mod.c, bignum_mod_raw.c). All other
 *  modules should use the high-level modular bignum interface (bignum_mod.h)
 *  or the legacy bignum interface (bignum.h).
 *
 *  Copyright The Mbed TLS Contributors
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

#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

/** Count leading zero bits in a given integer.
 *
 * \param a     Integer to count leading zero bits.
 *
 * \return      The number of leading zero bits in \p a.
 */
size_t mbedtls_mpi_core_clz( mbedtls_mpi_uint a );

/** Return the minimum number of bits required to represent the value held
 * in the MPI.
 *
 * \note This function returns 0 if all the limbs of \p A are 0.
 *
 * \param[in] A     The address of the MPI.
 * \param A_limbs   The number of limbs of \p A.
 *
 * \return      The number of bits in \p A.
 */
size_t mbedtls_mpi_core_bitlen( const mbedtls_mpi_uint *A, size_t A_limbs );

/** Convert a big-endian byte array aligned to the size of mbedtls_mpi_uint
 * into the storage form used by mbedtls_mpi.
 *
 * \param[in,out] A     The address of the MPI.
 * \param A_limbs       The number of limbs of \p A.
 */
void mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_uint *A,
                                         size_t A_limbs );

/** Import X from unsigned binary data, little-endian.
 *
 * The MPI needs to have enough limbs to store the full value (including any
 * most significant zero bytes in the input).
 *
 * \param[out] X         The address of the MPI.
 * \param X_limbs        The number of limbs of \p X.
 * \param[in] input      The input buffer to import from.
 * \param input_length   The length bytes of \p input.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p X isn't
 *               large enough to hold the value in \p input.
 */
int mbedtls_mpi_core_read_le( mbedtls_mpi_uint *X,
                              size_t X_limbs,
                              const unsigned char *input,
                              size_t input_length );

/** Import X from unsigned binary data, big-endian.
 *
 * The MPI needs to have enough limbs to store the full value (including any
 * most significant zero bytes in the input).
 *
 * \param[out] X        The address of the MPI.
 *                      May only be #NULL if \X_limbs is 0 and \p input_length
 *                      is 0.
 * \param X_limbs       The number of limbs of \p X.
 * \param[in] input     The input buffer to import from.
 *                      May only be #NULL if \p input_length is 0.
 * \param input_length  The length in bytes of \p input.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p X isn't
 *               large enough to hold the value in \p input.
 */
int mbedtls_mpi_core_read_be( mbedtls_mpi_uint *X,
                              size_t X_limbs,
                              const unsigned char *input,
                              size_t input_length );

/** Export A into unsigned binary data, little-endian.
 *
 * \note If \p output is shorter than \p A the export is still successful if the
 *       value held in \p A fits in the buffer (that is, if enough of the most
 *       significant bytes of \p A are 0).
 *
 * \param[in] A         The address of the MPI.
 * \param A_limbs       The number of limbs of \p A.
 * \param[out] output   The output buffer to export to.
 * \param output_length The length in bytes of \p output.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p output isn't
 *               large enough to hold the value of \p A.
 */
int mbedtls_mpi_core_write_le( const mbedtls_mpi_uint *A,
                               size_t A_limbs,
                               unsigned char *output,
                               size_t output_length );

/** Export A into unsigned binary data, big-endian.
 *
 * \note If \p output is shorter than \p A the export is still successful if the
 *       value held in \p A fits in the buffer (that is, if enough of the most
 *       significant bytes of \p A are 0).
 *
 * \param[in] A         The address of the MPI.
 * \param A_limbs       The number of limbs of \p A.
 * \param[out] output   The output buffer to export to.
 * \param output_length The length in bytes of \p output.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p output isn't
 *               large enough to hold the value of \p A.
 */
int mbedtls_mpi_core_write_be( const mbedtls_mpi_uint *A,
                               size_t A_limbs,
                               unsigned char *output,
                               size_t output_length );

#define ciL    ( sizeof(mbedtls_mpi_uint) )   /* chars in limb  */
#define biL    ( ciL << 3 )                   /* bits  in limb  */
#define biH    ( ciL << 2 )                   /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )
/* Get a specific byte, without range checks. */
#define GET_BYTE( X, i )                                \
    ( ( (X)[(i) / ciL] >> ( ( (i) % ciL ) * 8 ) ) & 0xff )

/** \brief         Compare a machine integer with an MPI.
 *
 *                 This function operates in constant time with respect
 *                 to the values of \p min and \p A.
 *
 * \param min      A machine integer.
 * \param[in] A    An MPI.
 * \param A_limbs  The number of limbs of \p A.
 *                 This must be at least 1.
 *
 * \return         1 if \p min is less than or equal to \p A, otherwise 0.
 */
unsigned mbedtls_mpi_core_uint_le_mpi( mbedtls_mpi_uint min,
                                       const mbedtls_mpi_uint *A,
                                       size_t A_limbs );

/** \brief              Shift a machine integer right by a number of bits.
 *
 *                      Shifting by more bits than there are bit positions
 *                      in \p X is valid and results in setting \p X to 0.
 *
 *                      This function's execution time depends on the value
 *                      of \p count (and of course \p limbs).
 *
 * \param[in,out] X     The number to shift.
 * \param limbs         The number of limbs of \p X. This must be at least 1.
 * \param count         The number of bits to shift by.
 */
void mbedtls_mpi_core_shift_r( mbedtls_mpi_uint *X, size_t limbs,
                               size_t count );

/**
 * \brief          Fill an integer with a number of random bytes.
 *
 * \param X        The destination MPI.
 * \param X_limbs  The number of limbs of \p X.
 * \param bytes    The number of random bytes to generate.
 * \param f_rng    The RNG function to use. This must not be \c NULL.
 * \param p_rng    The RNG parameter to be passed to \p f_rng. This may be
 *                 \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return         \c 0 if successful.
 * \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \p X does not have
 *                 enough room for \p bytes bytes.
 * \return         A negative error code on RNG failure.
 *
 * \note           The bytes obtained from the RNG are interpreted
 *                 as a big-endian representation of an MPI; this can
 *                 be relevant in applications like deterministic ECDSA.
 */
int mbedtls_mpi_core_fill_random( mbedtls_mpi_uint *X, size_t X_limbs,
                                  size_t bytes,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng );

/** Generate a random number uniformly in a range.
 *
 * This function generates a random number between \p min inclusive and
 * \p N exclusive.
 *
 * The procedure complies with RFC 6979 §3.3 (deterministic ECDSA)
 * when the RNG is a suitably parametrized instance of HMAC_DRBG
 * and \p min is \c 1.
 *
 * \note           There are `N - min` possible outputs. The lower bound
 *                 \p min can be reached, but the upper bound \p N cannot.
 *
 * \param X        The destination MPI.
 * \param X_limbs  The number of limbs of \p X.
 *                 This must be at least \p N_limbs.
 * \param min      The minimum value to return.
 *                 It must be nonnegative.
 * \param N        The upper bound of the range, exclusive.
 *                 In other words, this is one plus the maximum value to return.
 *                 \p N must be strictly larger than \p min.
 * \param N_limbs  The number of limbs of \p N.
 * \param f_rng    The RNG function to use. This must not be \c NULL.
 * \param p_rng    The RNG parameter to be passed to \p f_rng.
 *
 * \return         \c 0 if successful.
 * \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \p min or \p N is invalid
 *                 or if they are incompatible
 *                 or if \p X_limbs is too small (less than \p N_limbs).
 * \return         #MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the implementation was
 *                 unable to find a suitable value within a limited number
 *                 of attempts. This has a negligible probability if \p N
 *                 is significantly larger than \p min, which is the case
 *                 for all usual cryptographic applications.
 * \return         Another negative error code on failure.
 */
int mbedtls_mpi_core_random( mbedtls_mpi_uint *X, size_t X_limbs,
                             mbedtls_mpi_sint min,
                             const mbedtls_mpi_uint *N, size_t N_limbs,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng );

#endif /* MBEDTLS_BIGNUM_CORE_H */
