/* Common code between clients and services */

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

#include "common.h"
int __psa_ff_client_security_state = NON_SECURE;

#if 0
static void _printbits(uint32_t num)
{
    for (int i = 0; i < 32; i++) {
        if ((num >> (31-i) & 0x1)) {
            INFO("1");
        } else {
            INFO("0");
        }
    }
    INFO("\n");
}
#endif
