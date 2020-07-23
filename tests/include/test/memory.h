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

#if defined(MBEDTLS_TEST_MEMORY_WRAPPERS)

#include <stddef.h>

/** Hook to call immediately before starting to execute a test case.
 */
void mbedtls_test_memory_setup( void );

/** Hook to call immediately after executing a test case, after establishing
 * its pass/fail status but before printing out the outcome.
 */
void mbedtls_test_memory_teardown( void );

/** Statistics about memory usage.
 *
 * Calls to mbedtls_calloc() with a size of 0 and calls to
 * mbedtls_free(NULL) are not included in these statistics.
 *
 * The statistics assume that a block allocated before a call to
 * mbedtls_test_memory_setup() is never freed after this call.
 */
typedef struct
{
    /** The total number of calls to mbedtls_calloc(). */
    size_t allocations;
    /** The total number of allocated bytes. This is typically a lot larger
     * than the peak memory consumption. */
    size_t bytes;
    /** The number of failed allocations. */
    size_t failed;
    /** The number of calls to mbedtls_calloc() minus the number of calls
     * to mbedtls_free(). */
    size_t active;
} mbedtls_test_memory_stats_t;

/** Obtain statistics about allocations since the last call to
 * mbedtls_test_memory_setup().
 */
void mbedtls_test_memory_get_stats( mbedtls_test_memory_stats_t *stats );

/** Obtain statistics about allocations since the program startup.
 */
void mbedtls_test_memory_get_total_stats( mbedtls_test_memory_stats_t *stats );

#include "memory_wrappers.h"

#else /* MBEDTLS_TEST_MEMORY_WRAPPERS */

/* If the wrappers are disabled, define hooks that do nothing. */
#define mbedtls_test_memory_setup( ) ( (void) 0 )
#define mbedtls_test_memory_teardown( ) ( (void) 0 )

/* Make the wrappers available for the sake of the few test cases that
 * allocate memory that is freed in library code or vice versa. */
#define mbedtls_test_calloc_wrapper( n, size ) mbedtls_calloc( n, size )
#define mbedtls_test_free_wrapper( ptr ) mbedtls_free( ptr )

#endif /* MBEDTLS_TEST_MEMORY_WRAPPERS */

#endif /* TEST_MEMORY_H */
