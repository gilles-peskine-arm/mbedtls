/*
 * Test driver for cipher functions.
 * Currently only supports multi-part operations using AES-CTR.
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

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa/crypto.h"
#include "mbedtls/cipher.h"

#include "drivers/cipher.h"

#include "test/random.h"

#include <string.h>

/* If non-null, on success, copy this to the output. */
void *test_driver_cipher_forced_output = NULL;
size_t test_driver_cipher_forced_output_length = 0;

/* Test driver implements AES-CTR by default when it's status is not overridden.
 * Set test_transparent_cipher_status to PSA_ERROR_NOT_SUPPORTED to use fallback
 * even for AES-CTR.
 * Keep in mind this code is only exercised during the crypto drivers test target,
 * meaning the other test runs will still test only the non-driver implementation. */
psa_status_t test_transparent_cipher_status = PSA_SUCCESS;
unsigned long test_transparent_cipher_hit = 0;

psa_status_t test_transparent_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    test_transparent_cipher_hit++;

    if( test_transparent_cipher_status != PSA_SUCCESS )
        return test_transparent_cipher_status;
    if( output_size < test_driver_cipher_forced_output_length )
        return PSA_ERROR_BUFFER_TOO_SMALL;

    memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
    *output_length = test_driver_cipher_forced_output_length;

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    test_transparent_cipher_hit++;

    if( test_transparent_cipher_status != PSA_SUCCESS )
        return test_transparent_cipher_status;
    if( output_size < test_driver_cipher_forced_output_length )
        return PSA_ERROR_BUFFER_TOO_SMALL;

    memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
    *output_length = test_driver_cipher_forced_output_length;

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_encrypt_setup(
    test_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    int ret = 0;

    test_transparent_cipher_hit++;

    if( operation->alg != 0 )
        return PSA_ERROR_BAD_STATE;

    /* write our struct, this will trigger memory corruption failures
     * in test when we go outside of bounds, or when the function is called
     * without first destroying the context object. */
    memset(operation, 0, sizeof(test_transparent_cipher_operation_t));

    /* Test driver supports AES-CTR only, to verify operation calls. */
    if( alg != PSA_ALG_CTR || psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES )
        return PSA_ERROR_NOT_SUPPORTED;

    operation->alg = alg;
    operation->iv_size = 16;
    operation->block_size = 16;

    cipher_info = mbedtls_cipher_info_from_values( MBEDTLS_CIPHER_ID_AES,
                                                   key_length * 8,
                                                   MBEDTLS_MODE_CTR );
    if( cipher_info == NULL )
        return PSA_ERROR_NOT_SUPPORTED;

    mbedtls_cipher_init( &operation->cipher );

    ret = mbedtls_cipher_setup( &operation->cipher, cipher_info );
    if( ret != 0 ) {
        mbedtls_cipher_free( &operation->cipher );
        return mbedtls_to_psa_error( ret );
    }

    ret = mbedtls_cipher_setkey( &operation->cipher,
                                 key,
                                 key_length * 8, MBEDTLS_ENCRYPT );
    if( ret != 0 ) {
        mbedtls_cipher_free( &operation->cipher );
        return mbedtls_to_psa_error( ret );
    }

    operation->iv_set = 0;
    operation->iv_required = 1;
    operation->key_set = 1;

    /* Allow overriding return value for testing purposes */
    if( test_transparent_cipher_status != PSA_SUCCESS )
        mbedtls_cipher_free( &operation->cipher );

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_decrypt_setup(
    test_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
const mbedtls_cipher_info_t *cipher_info = NULL;
    int ret = 0;

    test_transparent_cipher_hit++;

    if( operation->alg != 0 )
        return PSA_ERROR_BAD_STATE;

    /* write our struct, this will trigger memory corruption failures
     * in test when we go outside of bounds, or when the function is called
     * without first destroying the context object. */
    memset(operation, 0, sizeof(test_transparent_cipher_operation_t));

    /* Test driver supports AES-CTR only, to verify operation calls. */
    if( alg != PSA_ALG_CTR || psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES )
        return PSA_ERROR_NOT_SUPPORTED;

    operation->alg = alg;
    operation->iv_size = 16;
    operation->block_size = 16;

    mbedtls_cipher_init( &operation->cipher );

    cipher_info = mbedtls_cipher_info_from_values( MBEDTLS_CIPHER_ID_AES,
                                                   key_length * 8,
                                                   MBEDTLS_MODE_CTR );
    if( cipher_info == NULL )
        return PSA_ERROR_NOT_SUPPORTED;

    ret = mbedtls_cipher_setup( &operation->cipher, cipher_info );
    if( ret != 0 )
        return mbedtls_to_psa_error( ret );

    ret = mbedtls_cipher_setkey( &operation->cipher,
                                 key,
                                 key_length * 8, MBEDTLS_DECRYPT );
    if( ret != 0 )
        return mbedtls_to_psa_error( ret );

    operation->iv_set = 0;
    operation->iv_required = 1;
    operation->key_set = 1;

    /* Allow overriding return value for testing purposes */
    if( test_transparent_cipher_status != PSA_SUCCESS )
        mbedtls_cipher_free( &operation->cipher );

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_abort(
    test_transparent_cipher_operation_t *operation)
{
    if( operation->alg == 0 )
        return( PSA_SUCCESS );
    if( operation->alg != PSA_ALG_CTR )
        return( PSA_ERROR_BAD_STATE );

    mbedtls_cipher_free( &operation->cipher );

    /* write our struct, this will trigger memory corruption failures
     * in test when we go outside of bounds. */
    memset(operation, 0, sizeof(test_transparent_cipher_operation_t));

    test_transparent_cipher_hit++;
    return PSA_SUCCESS;
}

psa_status_t test_transparent_cipher_generate_iv(
    test_transparent_cipher_operation_t *operation,
    uint8_t *iv,
    size_t iv_size,
    size_t *iv_length)
{
    psa_status_t status;
    mbedtls_test_rnd_pseudo_info rnd_info;
    memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

    test_transparent_cipher_hit++;

    if( operation->alg != PSA_ALG_CTR )
        return( PSA_ERROR_BAD_STATE );

    if( operation->iv_set || ! operation->iv_required )
        return( PSA_ERROR_BAD_STATE );

    if( iv_size < operation->iv_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    status = mbedtls_to_psa_error(
        mbedtls_test_rnd_pseudo_rand( &rnd_info,
                                      iv,
                                      operation->iv_size ) );
    if( status != PSA_SUCCESS )
        return status;

    *iv_length = operation->iv_size;
    status = test_transparent_cipher_set_iv( operation, iv, *iv_length );

    return status;
}

psa_status_t test_transparent_cipher_set_iv(
    test_transparent_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    psa_status_t status;

    test_transparent_cipher_hit++;

    if( operation->alg != PSA_ALG_CTR )
        return PSA_ERROR_BAD_STATE;

    if( operation->iv_set || ! operation->iv_required )
        return( PSA_ERROR_BAD_STATE );

    if( iv_length != operation->iv_size )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = mbedtls_to_psa_error(
        mbedtls_cipher_set_iv( &operation->cipher, iv, iv_length ) );

    if( status == PSA_SUCCESS )
        operation->iv_set = 1;

    return status;
}

psa_status_t test_transparent_cipher_update(
    test_transparent_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    size_t expected_output_size;
    psa_status_t status;

    test_transparent_cipher_hit++;

    if( operation->alg != PSA_ALG_CTR )
        return( PSA_ERROR_BAD_STATE );

    expected_output_size = ( operation->cipher.unprocessed_len + input_length )
                           / operation->block_size * operation->block_size;

    if( output_size < expected_output_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    status = mbedtls_to_psa_error(
        mbedtls_cipher_update( &operation->cipher, input,
                               input_length, output, output_length ) );

    if( status != PSA_SUCCESS )
        return status;

    if( test_driver_cipher_forced_output != NULL )
    {
        if( output_size < test_driver_cipher_forced_output_length )
            return PSA_ERROR_BUFFER_TOO_SMALL;

        memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
        *output_length = test_driver_cipher_forced_output_length;
    }

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_finish(
    test_transparent_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t temp_output_buffer[MBEDTLS_MAX_BLOCK_LENGTH];

    test_transparent_cipher_hit++;

    if( operation->alg != PSA_ALG_CTR )
        return( PSA_ERROR_BAD_STATE );

    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );

    if( operation->iv_required && ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );

    status = mbedtls_to_psa_error(
        mbedtls_cipher_finish( &operation->cipher,
                               temp_output_buffer,
                               output_length ) );

    mbedtls_cipher_free( &operation->cipher );

    if( status != PSA_SUCCESS )
        return( status );

    if( *output_length == 0 )
        ; /* Nothing to copy. Note that output may be NULL in this case. */
    else if( output_size >= *output_length )
        memcpy( output, temp_output_buffer, *output_length );
    else
        return( PSA_ERROR_BUFFER_TOO_SMALL );


    if( test_driver_cipher_forced_output != NULL )
    {
        if( output_size < test_driver_cipher_forced_output_length )
            return PSA_ERROR_BUFFER_TOO_SMALL;

        memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
        *output_length = test_driver_cipher_forced_output_length;
    }

    return test_transparent_cipher_status;
}

/*
 * opaque versions, to do
 */
psa_status_t test_opaque_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_encrypt_setup(
    test_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_decrypt_setup(
    test_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_abort(
    test_opaque_cipher_operation_t *operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_generate_iv(
    test_opaque_cipher_operation_t *operation,
    uint8_t *iv,
    size_t iv_size,
    size_t *iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_size;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_set_iv(
    test_opaque_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_update(
    test_opaque_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_finish(
    test_opaque_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
