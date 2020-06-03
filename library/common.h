/**
 * \file common.h
 *
 * \brief Utility macros for internal use in the library
 */
/*
 *  Copyright (C) 2019, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_LIBRARY_COMMON_H
#define MBEDTLS_LIBRARY_COMMON_H

#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

/* Force the inclusion of check_config.h, whether config.h included it or not.
 * This makes it impossible for users who write their own config.h to
 * accidentally define an unsupported configuration which may not have
 * the intended effect.
 */
#include "mbedtls/check_config.h"

/* We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */
#include <limits.h>
#if CHAR_BIT != 8
#error "Mbed TLS requires a platform with 8-bit bytes (8-bit char type)."
#endif

/* We assume that int is a 32-bit type in many places. Some modules
 * don't compile if int is a 16-bit type. More dangerously, some of the code
 * compiles, but is vulnerable to integer overflows. Do not remove this check
 * without having done a thorough security review of your configuration.
 */
#if INT_MAX < 0x7fffffff
#error "Mbed TLS requires the int type to have 32 bits or more. 16-bit platforms are not supported and some of the code is insecure on 16-bit platforms."
#endif

/* In some places, we assume that size_t values will not be promoted. */
#include <stdint.h>
#if SIZE_MAX < UINT_MAX
#error "Mbed TLS requires size_t to be at least as wide as unsigned int."
#endif

/** Helper to define a function as static except when building invasive tests.
 *
 * If a function is only used inside its own source file and should be
 * declared `static` to allow the compiler to optimize for code size,
 * but that function has unit tests, define it with
 * ```
 * MBEDTLS_STATIC_TESTABLE int mbedtls_foo(...) { ... }
 * ```
 * and declare it in a header in the `library/` directory with
 * ```
 * #if defined(MBEDTLS_TEST_HOOKS)
 * int mbedtls_foo(...);
 * #endif
 * ```
 */
#if defined(MBEDTLS_TEST_HOOKS)
#define MBEDTLS_STATIC_TESTABLE
#else
#define MBEDTLS_STATIC_TESTABLE static
#endif

#endif /* MBEDTLS_LIBRARY_COMMON_H */
