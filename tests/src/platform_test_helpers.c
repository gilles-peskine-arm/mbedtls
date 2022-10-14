/*
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

#include <stdlib.h>
#include <string.h>

#include <test/helpers.h>
#include <test/macros.h>
#include <test/platform.h>

#if defined(MBEDTLS_TEST_PLATFORM_MACROS)

mbedtls_test_platform_function_counters_t mbedtls_test_platform_macro_counters;

void mbedtls_test_reset_platform_macro_counters( void )
{
    memset( &mbedtls_test_platform_macro_counters,
            0, sizeof( mbedtls_test_platform_macro_counters ) );
}

void *mbedtls_test_platform_calloc_macro( size_t nbmem, size_t size )
{
    ++mbedtls_test_platform_macro_counters.calloc;
    return( calloc( nbmem, size ) );
}

void mbedtls_test_platform_free_macro( void* ptr )
{
    ++mbedtls_test_platform_macro_counters.free;
    free( ptr );
}

#endif /* MBEDTLS_TEST_PLATFORM_MACROS */

#if defined(MBEDTLS_PLATFORM_C)

mbedtls_test_platform_function_counters_t mbedtls_test_platform_variable_counters;

void mbedtls_test_reset_platform_variable_counters( void )
{
    memset( &mbedtls_test_platform_variable_counters,
            0, sizeof( mbedtls_test_platform_variable_counters ) );
}

#if defined(MBEDTLS_TEST_PLATFORM_MEMORY_VARIABLES)
void *mbedtls_test_platform_calloc_variable( size_t nbmem, size_t size )
{
    ++mbedtls_test_platform_variable_counters.calloc;
    return( calloc( nbmem, size ) );
}

void mbedtls_test_platform_free_variable( void* ptr )
{
    ++mbedtls_test_platform_variable_counters.free;
    free( ptr );
}
#endif /* MBEDTLS_TEST_PLATFORM_MEMORY_VARIABLES */

#endif /* MBEDTLS_PLATFORM_C */
