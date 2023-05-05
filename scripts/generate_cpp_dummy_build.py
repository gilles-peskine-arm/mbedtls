#!/usr/bin/env python3

"""Generate a C++ dummy build program that includes all the headers.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import glob
import os
import re
import sys
from typing import Optional
from mbedtls_dev import build_tree
from mbedtls_dev import typing_util

CPP_TEMPLATE = """\
/* Automatically generated file. Do not edit.
 *
 *  This program is a dummy C++ program to ensure Mbed TLS library header files
 *  can be included and built with a C++ compiler.
 *
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

#include "mbedtls/build_info.h"

@HEADERS@

@UNDEFINE@
@HEADERS@

int main()
{
    mbedtls_platform_context *ctx = NULL;
    mbedtls_platform_setup(ctx);
    mbedtls_printf("CPP Build test passed\\n");
    mbedtls_platform_teardown(ctx);
}
"""

HEADERS_TO_SKIP = frozenset([
    'mbedtls/mbedtls_config.h',
    'psa/crypto_config.h',
    # Some of the psa/crypto_*.h headers are not meant to be included
    # directly. They do have include guards that make them no-ops if
    # psa/crypto.h has been included before. Since psa/crypto.h comes
    # before psa/crypto_*.h in the header enumeration, we don't need
    # to skip those headers.
])

HEADER_PATH_RE = re.compile(r'(?:\A|.*/)include/(.*)\Z')
def get_header_name(header_path: str) -> Optional[str]:
    """Given a header path, return the string to use in an include directive.

    Based on the heuristic that the headers are under a directory called
    ``include``.

    Skip headers listed in HEADERS_TO_SKIP.
    """
    m = HEADER_PATH_RE.search(header_path)
    assert m
    header_name = m.group(1)
    if header_name in HEADERS_TO_SKIP:
        return None
    else:
        return header_name

def undef_guard(header: str) -> str:
    """Given a header name, construct the corresponding double-inclusion guard."""
    symbol = re.sub(r'[^0-9_A-Z]', '_', header.upper())
    return '#undef {}\n'.format(symbol)

def generate_cpp_content(include_dir: str) -> str:
    """Generate C++ build test source code for the headers under include_dir."""
    content = CPP_TEMPLATE
    header_paths = sorted(glob.glob(os.path.join(include_dir, 'mbedtls/*.h')) +
                          glob.glob(os.path.join(include_dir, 'psa/*.h')))
    header_names = list(filter(None, (get_header_name(path)
                                      for path in header_paths)))
    include_all_headers = '\n'.join(['#include "{}"'.format(header)
                                     for header in header_names])
    content = content.replace('@HEADERS@', include_all_headers)
    undef_guards = '\n'.join([undef_guard(header)
                              for header in header_names])
    content = content.replace('@UNDEFINE@', undef_guards)
    return content

def generate_cpp_file(include_dir: str, output_file: str) -> None:
    """Generate C++ build test file for the headers under include_dir."""
    with open(output_file, 'w') as out:
        out.write(generate_cpp_content(include_dir))

def main(output_file: Optional[str] = None) -> None:
    """generate_cpp_dummy_build [OUTPUT_FILE]"""
    root = build_tree.guess_mbedtls_root()
    include_dir = os.path.join(root, 'include')
    if output_file is None:
        output_file = os.path.join(root, 'programs/test/cpp_dummy_build.cpp')
    generate_cpp_file(include_dir, output_file)

if __name__ == '__main__':
    main(*sys.argv[1:])
