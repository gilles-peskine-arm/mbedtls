/* PSA lifecycle states used by psasim. */

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

#define PSA_LIFECYCLE_PSA_STATE_MASK (0xff00u)
#define PSA_LIFECYCLE_IMP_STATE_MASK (0x00ffu)
#define PSA_LIFECYCLE_UNKNOWN (0x0000u)
#define PSA_LIFECYCLE_ASSEMBLY_AND_TEST (0x1000u)
#define PSA_LIFECYCLE_PSA_ROT_PROVISIONING (0x2000u)
#define PSA_LIFECYCLE_SECURED (0x3000u)
#define PSA_LIFECYCLE_NON_PSA_ROT_DEBUG (0x4000u)
#define PSA_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG (0x5000u)
#define PSA_LIFECYCLE_DECOMMISSIONED (0x6000u)
#define psa_rot_lifecycle_state(void) PSA_LIFECYCLE_UNKNOWN
