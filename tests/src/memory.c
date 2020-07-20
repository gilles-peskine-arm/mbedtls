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

#include <test/helpers.h>
#include <test/memory.h>
#include <test/memory_wrappers.h>

#if defined(MBEDTLS_TEST_MEMORY_WRAPPERS)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#endif

#include <string.h>

typedef struct
{
    size_t total_allocations; /* Total calls to calloc */
    size_t total_bytes; /* Total bytes allocated */
    size_t active_allocations; /* Calls to calloc that are not yet freed */
    size_t failed_allocations; /* Calls to calloc that have failed */
} mbedtls_test_memory_stats_t;
static mbedtls_test_memory_stats_t stats;

#if defined(MBEDTLS_TEST_MEMORY_CALLOC_FAILURE)
#include <stdbool.h>

typedef struct
{
    size_t fail_n; /* Fail the Nth allocation (counting from 0) */
    bool failed; /* A forced failure has happened */
} mbedtls_test_memory_calloc_forced_failures_t;
static mbedtls_test_memory_calloc_forced_failures_t forced_failures;
#endif /* MBEDTLS_TEST_MEMORY_CALLOC_FAILURE */

void mbedtls_test_memory_setup( void )
{
    memset( &stats, 0, sizeof( stats ) );

#if defined(MBEDTLS_TEST_MEMORY_CALLOC_FAILURE)
    /* Set up the forced failure plan for the first run: fail the first
     * allocation. See mbedtls_test_memory_next_forced_failure(). */
    memset( &forced_failures, 0, sizeof( forced_failures ) );
#endif /* MBEDTLS_TEST_MEMORY_CALLOC_FAILURE */
}

void mbedtls_test_memory_teardown( void )
{
}

void mbedtls_test_memory_get_stats( size_t *allocations, size_t *bytes,
                                    size_t *failed, size_t *leaks )
{
    *allocations = stats.total_allocations;
    *bytes = stats.total_bytes;
    *failed = stats.failed_allocations;
    *leaks = stats.active_allocations;
}

void *mbedtls_test_calloc_wrapper( size_t n, size_t size )
{
    /* Zero-size allocations do not count. This way, if the underlying calloc
     * function returns NULL, we know that the allocation has failed. */
    if( n == 0 || size == 0 )
        return( NULL );

    void *ptr = NULL;

#if defined(MBEDTLS_TEST_MEMORY_CALLOC_FAILURE)
    if( stats.total_allocations == forced_failures.fail_n )
    {
        forced_failures.failed = 1;
    }
    else
#endif
    {
        ptr = mbedtls_calloc( n, size );
    }

    ++stats.total_allocations;
    if( ptr == NULL )
    {
        ++stats.failed_allocations;
    }
    else
    {
        ++stats.active_allocations;
        stats.total_bytes += n * size;
    }
    return( ptr );
}

void mbedtls_test_free_wrapper( void *ptr )
{
    if( ptr == NULL )
        return;
    --stats.active_allocations;
    mbedtls_free( ptr );
}

#if defined(MBEDTLS_TEST_MEMORY_CALLOC_FAILURE)
bool mbedtls_test_memory_has_forced_failure( void )
{
    return( forced_failures.failed );
}

size_t mbedtls_test_memory_get_forced_failure( void )
{
    if( forced_failures.failed )
        return( forced_failures.fail_n );
    else
        return( -1 );
}

void mbedtls_test_memory_next_forced_failure( void )
{
    forced_failures.failed = 0;

    /* Successive runs of the test care will fail the Nth allocation, for
     * successive values of N. N starts at 0 (this is set in
     * mbedtls_test_memory_setup()). Eventually N will be larger than
     * the number of allocations that the test case performed, so the
     * test case will run normally (with no forced allocation failure).
     *
     * We don't try multiple failures. Most test cases give up after the
     * first allocation failure anyway.
     *
     * This works well only if the pattern of allocations performed by the
     * test case is the same on every run. This may not be the case with
     * randomized tests.
     */
    ++forced_failures.fail_n;

    memset( &stats, 0, sizeof( stats ) );
}
#endif

#endif /* MBEDTLS_TEST_MEMORY_WRAPPERS */
