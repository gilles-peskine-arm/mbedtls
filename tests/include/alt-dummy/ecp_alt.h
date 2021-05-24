/* ecp_alt.h with dummy types for MBEDTLS_ECP_ALT */
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

#ifndef ECP_ALT_H
#define ECP_ALT_H

typedef struct mbedtls_ecp_group
{
    int dummy;
}
mbedtls_ecp_group;

#if !defined(MBEDTLS_ECP_MAX_BITS)

#define MBEDTLS_ECP_MAX_BITS     521   
#endif

#define MBEDTLS_ECP_MAX_BYTES    ( ( MBEDTLS_ECP_MAX_BITS + 7 ) / 8 )
#define MBEDTLS_ECP_MAX_PT_LEN   ( 2 * MBEDTLS_ECP_MAX_BYTES + 1 )

#if !defined(MBEDTLS_ECP_WINDOW_SIZE)

#define MBEDTLS_ECP_WINDOW_SIZE    6   
#endif 

#if !defined(MBEDTLS_ECP_FIXED_POINT_OPTIM)

#define MBEDTLS_ECP_FIXED_POINT_OPTIM  1   
#endif 


#endif /* ecp_alt.h */
