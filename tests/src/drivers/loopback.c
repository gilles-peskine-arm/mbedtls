/*
 * Test driver for signature functions using a copy of Mbed TLS.
 */
/*  Copyright The Mbed TLS Contributors
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(PSA_CRYPTO_DRIVER_TEST_LOOPBACK)
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"

#include "test/drivers/signature.h"
#include "test/drivers/key_management.h"

#include "libcopy1/psa/crypto.h"

test_driver_signature_hooks_t test_driver_signature_sign_hooks = TEST_DRIVER_SIGNATURE_INIT;
test_driver_signature_hooks_t test_driver_signature_verify_hooks = TEST_DRIVER_SIGNATURE_INIT;
extern test_driver_key_management_hooks_t test_driver_key_management_hooks;

psa_status_t test_transparent_validate_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits )
{
    ++test_driver_key_management_hooks.hits;

    if( test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_key_management_hooks.forced_status );

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    libcopy1_psa_key_attributes_t lo_attributes = libcopy1_psa_key_attributes_init( );
    libcopy1_psa_key_id_t lo_id = 0;
    libcopy1_psa_set_key_type( &lo_attributes, psa_get_key_type( attributes ) );
    libcopy1_psa_set_key_bits( &lo_attributes, psa_get_key_bits( attributes ) );
    status = libcopy1_psa_import_key( &lo_attributes, data, data_length, &lo_id );
    if( status != PSA_SUCCESS )
        goto exit;
    status = libcopy1_psa_get_key_attributes( lo_id, &lo_attributes );
    if( status != PSA_SUCCESS )
        goto exit;
    *bits = libcopy1_psa_get_key_bits( &lo_attributes );

exit:
    libcopy1_psa_destroy_key( lo_id );
    libcopy1_psa_reset_key_attributes( &lo_attributes );
    return( status );
}

psa_status_t test_transparent_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    ++test_driver_signature_sign_hooks.hits;

    if( test_driver_signature_sign_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_signature_sign_hooks.forced_status );

    if( test_driver_signature_sign_hooks.forced_output != NULL )
    {
        if( test_driver_signature_sign_hooks.forced_output_length > signature_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( signature, test_driver_signature_sign_hooks.forced_output,
                test_driver_signature_sign_hooks.forced_output_length );
        *signature_length = test_driver_signature_sign_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    libcopy1_psa_key_attributes_t lo_attributes = libcopy1_psa_key_attributes_init( );
    libcopy1_psa_key_id_t lo_id = 0;
    libcopy1_psa_set_key_type( &lo_attributes, psa_get_key_type( attributes ) );
    libcopy1_psa_set_key_bits( &lo_attributes, psa_get_key_bits( attributes ) );
    libcopy1_psa_set_key_usage_flags( &lo_attributes, PSA_KEY_USAGE_SIGN_HASH );
    libcopy1_psa_set_key_algorithm( &lo_attributes, alg );
    status = libcopy1_psa_import_key( &lo_attributes, key, key_length, &lo_id );
    if( status != PSA_SUCCESS )
        goto exit;
    status = libcopy1_psa_sign_hash( lo_id, alg,
                                     hash, hash_length,
                                     signature, signature_size,
                                     signature_length );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    libcopy1_psa_destroy_key( lo_id );

    return( status );
}

psa_status_t test_opaque_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    ++test_driver_signature_verify_hooks.hits;

    if( test_driver_signature_verify_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_signature_verify_hooks.forced_status );

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    libcopy1_psa_key_attributes_t lo_attributes = libcopy1_psa_key_attributes_init( );
    libcopy1_psa_key_id_t lo_id = 0;
    libcopy1_psa_set_key_type( &lo_attributes, psa_get_key_type( attributes ) );
    libcopy1_psa_set_key_bits( &lo_attributes, psa_get_key_bits( attributes ) );
    libcopy1_psa_set_key_usage_flags( &lo_attributes, PSA_KEY_USAGE_VERIFY_HASH );
    libcopy1_psa_set_key_algorithm( &lo_attributes, alg );
    status = libcopy1_psa_import_key( &lo_attributes, key, key_length, &lo_id );
    if( status != PSA_SUCCESS )
        goto exit;
    status = libcopy1_psa_verify_hash( lo_id, alg,
                                       hash, hash_length,
                                       signature, signature_length );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    libcopy1_psa_destroy_key( lo_id );

    return( status );
}

psa_status_t test_opaque_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* PSA_CRYPTO_DRIVER_TEST_LOOPBACK */
