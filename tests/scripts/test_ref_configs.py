#!/usr/bin/env python3

"""Test reference configurations

For each reference configuration file in the configs directory, build the
configuration, run the test suites and, for some configurations, TLS tests.
If given one or more config name, only test these configurations.
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may
## not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
## WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

import argparse
import glob
import os
import shutil
import subprocess
from typing import List

CONFIGS_DIR = 'configs'
LIVE_CONFIG = 'include/mbedtls/mbedtls_config.h'
BACKUP_CONFIG = LIVE_CONFIG + '.bak'
SEEDFILE = 'tests/seedfile'
SEEDFILE_SIZE = 64

def test_configuration(config: str) -> None:
    """Test the given configuration.

    Assume that `prepare_for_testing` has run.
    Running `final_cleanup` may be necessary afterwards.
    """
    config_file = os.path.join(CONFIGS_DIR, config)
    env = os.environ.copy()
    env['MBEDTLS_TEST_CONFIGURATION'] = config
    # 1. Prepare
    print("""
******************************************
* Testing configuration: {}
******************************************
""".format(config))
    subprocess.check_call(['make', 'clean'])
    shutil.copy(config_file, LIVE_CONFIG)
    # 2. Build and run unit tests
    subprocess.check_call(['make'],
                          env=env)
    subprocess.check_call(['make', 'test'],
                          env=env)

def all_configurations() -> List[str]:
    """List the available configurations."""
    return [os.path.basename(path)
            for path in glob.glob(os.path.join(CONFIGS_DIR, '*.h'))]

def test_configurations(options) -> None:
    """Test the specified configurations."""
    for config in options.configs:
        test_configuration(config)

def prepare_for_testing() -> None:
    """Initial setup before running any tests."""
    shutil.copy(LIVE_CONFIG, BACKUP_CONFIG)
    # For configurations that enable MBEDTLS_ENTROPY_NV_SEED, ensure that
    # a seedfile is present.
    if not os.path.exists(SEEDFILE) or \
       os.stat(SEEDFILE).st_size < SEEDFILE_SIZE:
        with open(SEEDFILE, 'wb') as seedfile:
            seedfile.write(os.urandom(SEEDFILE_SIZE))

def final_cleanup() -> None:
    """Final cleanup after running all the tests."""
    shutil.move(BACKUP_CONFIG, LIVE_CONFIG)
    subprocess.check_call(['make', 'clean'])

def run_tests(options) -> None:
    """Test the specified configurations, then clean up."""
    prepare_for_testing()
    try:
        test_configurations(options)
    finally:
        final_cleanup()

def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('configs', nargs='*', metavar='CONFIGS',
                        help='Configurations to test (default: all)')
    options = parser.parse_args()
    if not options.configs:
        options.configs = all_configurations()
    run_tests(options)

if __name__ == '__main__':
    main()
