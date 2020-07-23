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

static mbedtls_test_memory_stats_t current_stats;
static mbedtls_test_memory_stats_t total_stats;

static void update_stats( mbedtls_test_memory_stats_t *stats )
{
    stats->allocations += current_stats.allocations;
    stats->bytes += current_stats.bytes;
    stats->failed += current_stats.failed;
    stats->active += current_stats.active;
}

void mbedtls_test_memory_setup( void )
{
    update_stats( &total_stats );
    memset( &current_stats, 0, sizeof( current_stats ) );
}

void mbedtls_test_memory_teardown( void )
{
}

void mbedtls_test_memory_get_stats( mbedtls_test_memory_stats_t *stats )
{
    *stats = current_stats;
}

void mbedtls_test_memory_get_total_stats( mbedtls_test_memory_stats_t *stats )
{
    *stats = total_stats;
    update_stats( stats );
}

void *mbedtls_test_calloc_wrapper( size_t n, size_t size )
{
    /* Zero-size allocations do not count. This way, if the underlying calloc
     * function returns NULL, we know that the allocation has failed. */
    if( n == 0 || size == 0 )
        return( NULL );
    ++current_stats.allocations;
    void *ptr = mbedtls_calloc( n, size );
    if( ptr == NULL )
    {
        ++current_stats.failed;
    }
    else
    {
        ++current_stats.active;
        current_stats.bytes += n * size;
    }
    return( ptr );
}

void mbedtls_test_free_wrapper( void *ptr )
{
    if( ptr == NULL )
        return;
    --current_stats.active;
    mbedtls_free( ptr );
}

#endif /* MBEDTLS_TEST_MEMORY_WRAPPERS */
