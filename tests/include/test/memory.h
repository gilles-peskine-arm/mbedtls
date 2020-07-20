/**
 * \file memory.h
 *
 * \brief   This file declares features related to instrumenting memory
 *          management in the library for benchmarking or testing purposes.
 */

/*
 *  Copyright (C) 2020, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef TEST_MEMORY_H
#define TEST_MEMORY_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_TEST_MEMORY_CALLOC_FAILURE)
/* Forced allocation failures are only possible with the memory wrappers. */
#define MBEDTLS_TEST_MEMORY_WRAPPERS
#endif

#if defined(MBEDTLS_TEST_MEMORY_WRAPPERS)

#include <stddef.h>

/** Hook to call immediately before starting to execute a test case.
 */
void mbedtls_test_memory_setup( void );

/** Hook to call immediately after executing a test case, after establishing
 * its pass/fail status but before printing out the outcome.
 */
void mbedtls_test_memory_teardown( void );

/** Obtain statistics about allocations since the last call to
 * mbedtls_test_memory_setup().
 *
 * \param allocations   The total number of calls to mbedtls_calloc()
 *                      (excluding zero-sized allocations).
 * \param bytes         The total number of allocated bytes.
 *                      This is typically a lot larger than the total
 *                      memory consumption.
 * \param failed        The number of failed allocations.
 * \param leaks         The number of calls to mbedtls_calloc() minus
 *                      the number of calls to mbedtls_free()
 *                      (excluding zero-sized allocations and calls to
 *                      `mbedtls_free(NULL)`).
 */
void mbedtls_test_memory_get_stats( size_t *allocations, size_t *bytes,
                                        size_t *failed, size_t *leaks );

#else /* MBEDTLS_TEST_MEMORY_WRAPPERS */

/* If the wrappers are disabled, define hooks that do nothing. */
#define mbedtls_test_memory_setup( ) ( (void) 0 )
#define mbedtls_test_memory_teardown( ) ( (void) 0 )

#endif /* MBEDTLS_TEST_MEMORY_WRAPPERS */

#if defined(MBEDTLS_TEST_MEMORY_CALLOC_FAILURE)
#include <stdbool.h>

/** Report whether there has been a forced memory allocation failure during
 * the current run of the test.
 *
 * \return Whether there has been a forced failure during the current test
 *         case run.
 */
bool mbedtls_test_memory_has_forced_failure( void );

/** Return the position of the forced failure in the current run.
 *
 * \return N such that the Nth allocation during this test run was forced
 *         to fail.
 * \return \c -1 if no allocation was forced to fail during this test run.
 */
size_t mbedtls_test_memory_get_forced_failure( void );

/** Prepare to run a test case again with the next location of forced
 * allocation failure.
 *
 * Run test cases in a loop like this:
 * ```
 * mbedtls_test_memory_setup( );
 * test_case( );
 * while( mbedtls_test_memory_has_forced_failure( ) )
 * {
 *    mbedtls_test_memory_next_forced_failure( );
 *    test_case( );
 * }
 * mbedtls_test_memory_teardown( );
 * ```
 *
 * Each run will force a failure of a call to mbedtls_calloc() at
 * successively later locations, with this function returning 1.
 *  Eventually the point of failure will not be reached, and in that case
 * this function returns 0.
 */
void mbedtls_test_memory_next_forced_failure( void );

#endif /* MBEDTLS_TEST_MEMORY_CALLOC_FAILURE */

#endif /* TEST_MEMORY_H */
