/**
 * \file mpi_contexts.h
 *
 * \brief Operation contexts for MPI-based mechanisms (excluding ECC).
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
#ifndef MBEDTLS_OPAQUE_MPI_CONTEXTS_H
#define MBEDTLS_OPAQUE_MPI_CONTEXTS_H
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_MPI_MAX_SIZE)
/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * ( Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits )
 *
 * Note: Calculations can temporarily result in larger MPIs. So the number
 * of limbs required (MBEDTLS_MPI_MAX_LIMBS) is higher.
 */
#define MBEDTLS_MPI_MAX_SIZE                              1024     /**< Maximum number of bytes for usable MPIs. */
#endif /* !MBEDTLS_MPI_MAX_SIZE */

/*
 * Define the base integer type, architecture-wise.
 *
 * 32 or 64-bit integer types can be forced regardless of the underlying
 * architecture by defining MBEDTLS_HAVE_INT32 or MBEDTLS_HAVE_INT64
 * respectively and undefining MBEDTLS_HAVE_ASM.
 *
 * Double-width integers (e.g. 128-bit in 64-bit architectures) can be
 * disabled by defining MBEDTLS_NO_UDBL_DIVISION.
 */
#if !defined(MBEDTLS_HAVE_INT32)
    #if defined(_MSC_VER) && defined(_M_AMD64)
/* Always choose 64-bit when using MSC */
        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif /* !MBEDTLS_HAVE_INT64 */
typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
    #elif defined(__GNUC__) && (                         \
    defined(__amd64__) || defined(__x86_64__)     || \
    defined(__ppc64__) || defined(__powerpc64__)  || \
    defined(__ia64__)  || defined(__alpha__)      || \
    (defined(__sparc__) && defined(__arch64__)) || \
    defined(__s390x__) || defined(__mips64)       || \
    defined(__aarch64__))
        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif /* MBEDTLS_HAVE_INT64 */
typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
        #if !defined(MBEDTLS_NO_UDBL_DIVISION)
/* mbedtls_t_udbl defined as 128-bit unsigned int */
typedef unsigned int mbedtls_t_udbl __attribute__((mode(TI)));
            #define MBEDTLS_HAVE_UDBL
        #endif /* !MBEDTLS_NO_UDBL_DIVISION */
    #elif defined(__ARMCC_VERSION) && defined(__aarch64__)
/*
 * __ARMCC_VERSION is defined for both armcc and armclang and
 * __aarch64__ is only defined by armclang when compiling 64-bit code
 */
        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif /* !MBEDTLS_HAVE_INT64 */
typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
        #if !defined(MBEDTLS_NO_UDBL_DIVISION)
/* mbedtls_t_udbl defined as 128-bit unsigned int */
typedef __uint128_t mbedtls_t_udbl;
            #define MBEDTLS_HAVE_UDBL
        #endif /* !MBEDTLS_NO_UDBL_DIVISION */
    #elif defined(MBEDTLS_HAVE_INT64)
/* Force 64-bit integers with unknown compiler */
typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
    #endif
#endif /* !MBEDTLS_HAVE_INT32 */

#if !defined(MBEDTLS_HAVE_INT64)
/* Default to 32-bit compilation */
    #if !defined(MBEDTLS_HAVE_INT32)
        #define MBEDTLS_HAVE_INT32
    #endif /* !MBEDTLS_HAVE_INT32 */
typedef  int32_t mbedtls_mpi_sint;
typedef uint32_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT32_MAX
    #if !defined(MBEDTLS_NO_UDBL_DIVISION)
typedef uint64_t mbedtls_t_udbl;
        #define MBEDTLS_HAVE_UDBL
    #endif /* !MBEDTLS_NO_UDBL_DIVISION */
#endif /* !MBEDTLS_HAVE_INT64 */

/*
 * Sanity check that exactly one of MBEDTLS_HAVE_INT32 or MBEDTLS_HAVE_INT64 is defined,
 * so that code elsewhere doesn't have to check.
 */
#if (!(defined(MBEDTLS_HAVE_INT32) || defined(MBEDTLS_HAVE_INT64))) || \
    (defined(MBEDTLS_HAVE_INT32) && defined(MBEDTLS_HAVE_INT64))
#error "Only 32-bit or 64-bit limbs are supported in bignum"
#endif

struct mbedtls_mpi {
    /** Pointer to limbs.
     *
     * This may be \c NULL if \c n is 0.
     */
    mbedtls_mpi_uint *MBEDTLS_PRIVATE(p);

    /** Sign: -1 if the mpi is negative, 1 otherwise.
     *
     * The number 0 must be represented with `s = +1`. Although many library
     * functions treat all-limbs-zero as equivalent to a valid representation
     * of 0 regardless of the sign bit, there are exceptions, so bignum
     * functions and external callers must always set \c s to +1 for the
     * number zero.
     *
     * Note that this implies that calloc() or `... = {0}` does not create
     * a valid MPI representation. You must call mbedtls_mpi_init().
     */
    signed short MBEDTLS_PRIVATE(s);

    /** Total number of limbs in \c p.  */
    unsigned short MBEDTLS_PRIVATE(n);
    /* Make sure that MBEDTLS_MPI_MAX_LIMBS fits in n.
     * Use the same limit value on all platforms so that we don't have to
     * think about different behavior on the rare platforms where
     * unsigned short can store values larger than the minimum required by
     * the C language, which is 65535.
     */
#if MBEDTLS_MPI_MAX_LIMBS > 65535
#error "MBEDTLS_MPI_MAX_LIMBS > 65535 is not supported"
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* mpi_contexts.h */
