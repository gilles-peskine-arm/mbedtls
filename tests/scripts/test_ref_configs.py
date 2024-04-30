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
import sys
import typing
from typing import Dict, Iterable, List

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
                 compat: Iterable[List[str]] = frozenset(),
                 opt: Iterable[List[str]] = frozenset(),
                 psa: bool = False):
        self.compat = compat
        self.opt = opt
        self.psa = psa

# Describe additional testing for some configurations. If a configuration is
# not listed here, this script only builds the library and runs the unit tests.
CONFIGS = {
    'config-ccm-psk-tls1_2.h': Spec(
        compat=[['-m', 'tls12', '-f', '^TLS-PSK-WITH-AES-...-CCM-8']],
        psa=True,
    ),
    'config-ccm-psk-dtls1_2.h': Spec(
        compat=[['-m', 'dtls12', '-f', '^TLS-PSK-WITH-AES-...-CCM-8']],
        psa=True,
    ),
    'config-suite-b.h': Spec(
        compat=[['-m', 'tls12', '-f', 'ECDHE-ECDSA.*AES.*GCM', '-p', 'mbedTLS']],
        psa=True,
    ),
    'config-symmetric-only.h': Spec(
        psa=False, # Uses PSA by default, no need to test it twice
    ),
    'config-thread.h': Spec(
        opt=[['-f', 'ECJPAKE.*nolog']],
        psa=True,
    ),
}

class TestOptions:
    """Runtime options for `test_configuration`."""
    #pylint: disable=too-few-public-methods

    keep_going = False #type: bool

def tweak_config(symbols_to_set: Iterable[str]) -> None:
    """Additionally set the given configuration options."""
    for symbol in symbols_to_set:
        subprocess.check_call(['scripts/config.py', 'set', symbol])

def test_configuration_variant(options: TestOptions,
                               config_name: str,
                               config_file: str,
                               spec: Spec = Spec(),
                               psa: bool = False) -> bool:
    """Test the specified configuration variant.

    Assume that `prepare_for_testing` has run.
    Running `final_cleanup` may be necessary afterwards.

    If `options.keep_going` is true, return True on success, False on failure.
    Otherwise raise an exception as soon as a failure occurs.
    """
    env = os.environ.copy()
    env['MBEDTLS_TEST_CONFIGURATION'] = config_name
    failures = [] #type: List[List[str]]
    def run(cmd: List[str], #pylint: disable=dangerous-default-value
            env: Dict[str, str] = env,
            **kwargs) -> bool:
        cp = subprocess.run(cmd,
                            env=env,
                            check=not options.keep_going,
                            **kwargs)
        if cp.returncode != 0:
            failures.append(cmd)
            return False
        return True
    # 1. Prepare
    print("""
******************************************
* Testing configuration: {}
******************************************
""".format(config_name))
    if not run(['make', 'clean']):
        return False
    shutil.copy(config_file, LIVE_CONFIG)
    if psa:
        tweak_config(['MBEDTLS_PSA_CRYPTO_C', 'MBEDTLS_USE_PSA_CRYPTO'])
    # 2. Build and run unit tests
    if not run(['make']):
        return False
    run(['make', 'test'])
    # 3. Run TLS tests
    for args in spec.compat:
        print("\nRunning compat.sh", *args)
        run(['tests/compat.sh'] + args)
    for args in spec.opt:
        print("\nRunning ssl-opt.sh", *args)
        run(['tests/ssl-opt.sh'] + args)
    # 4. In keep-going mode, report the failures
    return not failures

def all_configurations() -> List[str]:
    """List the available configurations."""
    return glob.glob(os.path.join(CONFIGS_DIR, '*.h'))

def test_configuration(options: TestOptions, config: str) -> int:
    """Test the given configuration.

    Assume that `prepare_for_testing` has run.
    Running `final_cleanup` may be necessary afterwards.

    If `options.keep_going` is true, return the number of failing variants
    (so 0 means success).
    Otherwise raise an exception as soon as a failure occurs.
    """
    if '/' in config:
        config_file = config
        config_name = os.path.basename(config)
    else:
        config_file = os.path.join(CONFIGS_DIR, config)
        config_name = config
    spec = CONFIGS.get(config_name, Spec())
    success = test_configuration_variant(options, config_name, config_file, spec)
    if spec.psa:
        success = success and \
            test_configuration_variant(options,
                                       config_name + '+PSA',
                                       config_file,
                                       spec,
                                       psa=True)
    return success

def test_configurations(options: TestOptions, configs: Iterable[str]) -> List[str]:
    """Test the specified configurations.

    If `options.keep_going` is true, return the list of failing
    configuration variants (so an empty list means success).
    Otherwise raise an exception as soon as a failure occurs.
    """
    failures = []
    for config in configs:
        if not test_configuration(options, config):
            failures.append(config)
    return failures

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

def run_tests(options: TestOptions, configs: List[str]) -> List[str]:
    """Test the specified configurations, then clean up.

    If `options.keep_going` is true, return the number of failing variants
    (so 0 means success).
    Otherwise raise an exception as soon as a failure occurs.
    """
    prepare_for_testing()
    try:
        return test_configurations(options, configs)
    finally:
        final_cleanup()

def report_tests(options: TestOptions, configs: List[str]) -> int:
    """Test the specified configurations, then clean up.

    If `options.keep_going` is true, return the number of failing variants
    (so 0 means success).
    Otherwise raise an exception as soon as a failure occurs.
    """
    failures = run_tests(options, configs)
    if failures:
        # The number of failures counts configuration variants:
        # foo.h and foo.h+PSA together count as 2.
        print('{}: FAILED: {}'.format(sys.argv[0], ' '.join(failures)))
    else:
        # The number of passes counts configurations:
        # foo.h and foo.h+PSA together count as 1.
        print('{}: {} PASSED'.format(sys.argv[0], len(configs)))
    return len(failures)

def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep-going', '-k',
                        action='store_true', default=False,
                        help='Keep going after an error')
    parser.add_argument('--stop', '-S',
                        action='store_false', dest='keep_going',
                        help='Stop on error (opposite of --keep-going)')
    parser.add_argument('configs', nargs='*', metavar='CONFIGS',
                        help=('Configurations to test'
                              ' (files; relative to configs/ if no slash;'
                              ' default: all in configs/)'))
    options = parser.parse_args()
    configs = options.configs if options.configs else all_configurations()
    sys.exit(report_tests(typing.cast(TestOptions, options), configs))

if __name__ == '__main__':
    main()
