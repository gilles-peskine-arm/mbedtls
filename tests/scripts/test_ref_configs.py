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
from typing import Iterable, List

CONFIGS_DIR = 'configs'
LIVE_CONFIG = 'include/mbedtls/mbedtls_config.h'
BACKUP_CONFIG = LIVE_CONFIG + '.bak'
SEEDFILE = 'tests/seedfile'
SEEDFILE_SIZE = 64

class Spec:
    """Specification of additional testing for a configuration."""
    # In Python >=3.6, this could be a typing.NamedTuple. But Python 3.5
    # doesn't have NamedTuple with both types and default values.
    #pylint: disable=too-few-public-methods

    def __init__(self,
                 psa: bool = False):
        self.psa = psa

# Describe additional testing for some configurations. If a configuration is
# not listed here, this script only builds the library and runs the unit tests.
CONFIGS = {
    'config-ccm-psk-tls1_2.h': Spec(
        psa=True,
    ),
    'config-ccm-psk-dtls1_2.h': Spec(
        psa=True,
    ),
    'config-suite-b.h': Spec(
        psa=True,
    ),
    'config-symmetric-only.h': Spec(
        psa=False, # Uses PSA by default, no need to test it twice
    ),
    'config-thread.h': Spec(
        psa=True,
    ),
}

def tweak_config(symbols_to_set: Iterable[str]) -> None:
    """Additionally set the given configuration options."""
    for symbol in symbols_to_set:
        subprocess.check_call(['scripts/config.py', 'set', symbol])

def test_configuration_variant(config_name: str,
                               config_file: str,
                               psa: bool = False) -> None:
    """Test the specified configuration variant.

    Assume that `prepare_for_testing` has run.
    Running `final_cleanup` may be necessary afterwards.
    """
    env = os.environ.copy()
    env['MBEDTLS_TEST_CONFIGURATION'] = config_name
    # 1. Prepare
    print("""
******************************************
* Testing configuration: {}
******************************************
""".format(config_name))
    subprocess.check_call(['make', 'clean'])
    shutil.copy(config_file, LIVE_CONFIG)
    if psa:
        tweak_config(['MBEDTLS_PSA_CRYPTO_C', 'MBEDTLS_USE_PSA_CRYPTO'])
    # 2. Build and run unit tests
    subprocess.check_call(['echo', 'make'],
                          env=env)
    subprocess.check_call(['echo', 'make', 'test'],
                          env=env)

def all_configurations() -> List[str]:
    """List the available configurations."""
    return glob.glob(os.path.join(CONFIGS_DIR, '*.h'))

def test_configuration(config: str) -> None:
    """Test the given configuration.

    Assume that `prepare_for_testing` has run.
    Running `final_cleanup` may be necessary afterwards.
    """
    if '/' in config:
        config_file = config
        config_name = os.path.basename(config)
    else:
        config_file = os.path.join(CONFIGS_DIR, config)
        config_name = config
    spec = CONFIGS.get(config_name, Spec())
    test_configuration_variant(config_name, config_file)
    if spec.psa:
        test_configuration_variant(config_name + '+PSA', config_file, psa=True)

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
                        help=('Configurations to test'
                              ' (files; relative to configs/ if no slash;'
                              ' default: all in configs/)'))
    options = parser.parse_args()
    if not options.configs:
        options.configs = all_configurations()
    run_tests(options)

if __name__ == '__main__':
    main()
