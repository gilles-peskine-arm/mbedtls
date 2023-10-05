/* psasim test client */

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

#include <psa/client.h>
#include "psa_manifest/sid.h"
#include <stdio.h>
#include <unistd.h>

int main()
{

    const char *text = "FOOBARCOOL!!";

    char output[100] = { 0 };
    printf("My PID is %d\n", getpid());

    printf("The version of the service is %u\n", psa_version(PSA_SID_SHA256_SID));
    psa_handle_t h = psa_connect(PSA_SID_SHA256_SID, 1);

    if (h < 0) {
        printf("Couldn't connect %d\n", h);
        return 1;
    } else {
        int type = 2;
        puts("Calling!");
        puts("Trying without invec");
        printf("Answer to my call was %d (no invec)\n", psa_call(h, type, NULL, 0, NULL, 0));
        psa_invec invecs[1];
        psa_outvec outvecs[1];
        invecs[0].base = text;
        invecs[0].len = 24;
        outvecs[0].base = output;
        outvecs[0].len = 99;

        printf("My iovec size should be %lu\n", invecs[0].len);
        printf("Answer to my call was %d (with invec)\n", psa_call(h, type, invecs, 1, outvecs, 1));
        printf("Here's the payload I recieved: %s\n", output);
        printf("Apparently the server wrote %lu bytes in outvec %d\n", outvecs[0].len, 0);
        puts("Closing handle");
        psa_close(h);
    }

    return 0;
}
