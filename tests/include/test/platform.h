/** Utilities for testing platform functions.
 */

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

#ifndef MBEDTLS_TEST_PLATFORM_H
#define MBEDTLS_TEST_PLATFORM_H

typedef struct
{
    size_t calloc;
    size_t free;
} mbedtls_test_platform_function_counters_t;

#if defined(MBEDTLS_TEST_PLATFORM_MACROS)

extern mbedtls_test_platform_function_counters_t mbedtls_test_platform_macro_counters;

void mbedtls_test_reset_platform_macro_counters( void );

void *mbedtls_test_platform_calloc_macro( size_t nbmem, size_t size );
void mbedtls_test_platform_free_macro( void* ptr );

#endif /* MBEDTLS_TEST_PLATFORM_MACROS */

#if defined(MBEDTLS_PLATFORM_C)

extern mbedtls_test_platform_function_counters_t mbedtls_test_platform_variable_counters;

void mbedtls_test_reset_platform_variable_counters( void );

#if defined(MBEDTLS_PLATFORM_MEMORY) &&                 \
    !( defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&        \
       defined(MBEDTLS_PLATFORM_FREE_MACRO) )
#define MBEDTLS_TEST_PLATFORM_MEMORY_VARIABLES
#endif

#if defined(MBEDTLS_TEST_PLATFORM_MEMORY_VARIABLES)
void *mbedtls_test_platform_calloc_variable( size_t nbmem, size_t size );
void mbedtls_test_platform_free_variable( void* ptr );
#endif /* MBEDTLS_TEST_PLATFORM_MEMORY_VARIABLES */

#endif /* MBEDTLS_PLATFORM_C */

#endif /* MBEDTLS_TEST_PLATFORM_H */
