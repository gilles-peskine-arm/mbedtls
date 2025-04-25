/*
 *  Mbed TLS configuration checks
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* Consistency checks on the user's configuration.
 * Check that it doesn't define macros that we assume are under full
 * control of the library, or options from past major versions that
 * no longer have any effect.
 * These headers are automatically generated. See
 * framework/scripts/mbedtls_framework/config_checks_generator.py
 */
#include "mbedtls_config_check_before.h"
#define MBEDTLS_INCLUDE_AFTER_RAW_CONFIG "mbedtls_config_check_after.h"

#include <mbedtls/build_info.h>

/* Consistency checks in the configuration: check for incompatible options,
 * missing options when at least one of a set needs to be enabled, etc. */
#include "mbedtls_check_config.h"
