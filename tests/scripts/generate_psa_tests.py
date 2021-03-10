#!/usr/bin/env python3
"""Generate test data for PSA cryptographic mechanisms.
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

import argparse
import os
import re
import sys
from typing import FrozenSet, Iterable, Iterator, List, Optional, Tuple, TypeVar

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import crypto_knowledge
from mbedtls_dev import macro_collector
from mbedtls_dev import psa_storage
from mbedtls_dev import test_case

T = TypeVar('T') #pylint: disable=invalid-name


def psa_want_symbol(name: str) -> str:
    """Return the PSA_WANT_xxx symbol associated with a PSA crypto feature."""
    if name.startswith('PSA_'):
        return name[:4] + 'WANT_' + name[4:]
    else:
        raise ValueError('Unable to determine the PSA_WANT_ symbol for ' + name)

def finish_family_dependency(dep: str, bits: int) -> str:
    """Finish dep if it's a family dependency symbol prefix.

    A family dependency symbol prefix is a PSA_WANT_ symbol that needs to be
    qualified by the key size. If dep is such a symbol, finish it by adjusting
    the prefix and appending the key size. Other symbols are left unchanged.
    """
    return re.sub(r'_FAMILY_(.*)', r'_\1_' + str(bits), dep)

def finish_family_dependencies(dependencies: List[str], bits: int) -> List[str]:
    """Finish any family dependency symbol prefixes.

    Apply `finish_family_dependency` to each element of `dependencies`.
    """
    return [finish_family_dependency(dep, bits) for dep in dependencies]

def automatic_dependencies(*expressions: str) -> List[str]:
    """Infer dependencies of a test case by looking for PSA_xxx symbols.

    The arguments are strings which should be C expressions. Do not use
    string literals or comments as this function is not smart enough to
    skip them.
    """
    used = set()
    for expr in expressions:
        used.update(re.findall(r'PSA_(?:ALG|ECC_FAMILY|KEY_TYPE)_\w+', expr))
    return sorted(psa_want_symbol(name) for name in used)

# A temporary hack: at the time of writing, not all dependency symbols
# are implemented yet. Skip test cases for which the dependency symbols are
# not available. Once all dependency symbols are available, this hack must
# be removed so that a bug in the dependency symbols proprely leads to a test
# failure.
def read_implemented_dependencies(filename: str) -> FrozenSet[str]:
    return frozenset(symbol
                     for line in open(filename)
                     for symbol in re.findall(r'\bPSA_WANT_\w+\b', line))
IMPLEMENTED_DEPENDENCIES = read_implemented_dependencies('include/psa/crypto_config.h')
def hack_dependencies_not_implemented(dependencies: List[str]) -> None:
    if not all(dep.lstrip('!') in IMPLEMENTED_DEPENDENCIES
               for dep in dependencies):
        dependencies.append('DEPENDENCY_NOT_IMPLEMENTED_YET')

def test_case_for_key_type_not_supported(
        verb: str, key_type: str, bits: int,
        dependencies: List[str],
        *args: str,
        param_descr: str = ''
) -> test_case.TestCase:
    """Return one test case exercising a key creation method
    for an unsupported key type or size.
    """
    hack_dependencies_not_implemented(dependencies)
    tc = test_case.TestCase()
    short_key_type = re.sub(r'PSA_(KEY_TYPE|ECC_FAMILY)_', r'', key_type)
    adverb = 'not' if dependencies else 'never'
    if param_descr:
        adverb = param_descr + ' ' + adverb
    tc.set_description('PSA {} {} {}-bit {} supported'
                       .format(verb, short_key_type, bits, adverb))
    tc.set_dependencies(dependencies)
    tc.set_function(verb + '_not_supported')
    tc.set_arguments([key_type] + list(args))
    return tc

class TestGenerator:
    """Gather information and generate test data."""

    def __init__(self, options):
        self.test_suite_directory = self.get_option(options, 'directory',
                                                    'tests/suites')
        self.constructors = self.read_psa_interface()

    @staticmethod
    def get_option(options, name: str, default: T) -> T:
        value = getattr(options, name, None)
        return default if value is None else value

    @staticmethod
    def remove_unwanted_macros(
            constructors: macro_collector.PSAMacroCollector
    ) -> None:
        # Mbed TLS doesn't support DSA. Don't attempt to generate any related
        # test case.
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_KEY_PAIR')
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_PUBLIC_KEY')
        constructors.algorithms_from_hash.pop('PSA_ALG_DSA', None)
        constructors.algorithms_from_hash.pop('PSA_ALG_DETERMINISTIC_DSA', None)

    def read_psa_interface(self) -> macro_collector.PSAMacroCollector:
        """Return the list of known key types, algorithms, etc."""
        constructors = macro_collector.PSAMacroCollector()
        header_file_names = ['include/psa/crypto_values.h',
                             'include/psa/crypto_extra.h']
        for header_file_name in header_file_names:
            with open(header_file_name, 'rb') as header_file:
                constructors.read_file(header_file)
        self.remove_unwanted_macros(constructors)
        return constructors

    def write_test_data_file(self, basename: str,
                             test_cases: Iterable[test_case.TestCase]) -> None:
        """Write the test cases to a .data file.

        The output file is ``basename + '.data'`` in the test suite directory.
        """
        filename = os.path.join(self.test_suite_directory, basename + '.data')
        test_case.write_data_file(filename, test_cases)

    ALWAYS_SUPPORTED = frozenset([
        'PSA_KEY_TYPE_DERIVE',
        'PSA_KEY_TYPE_RAW_DATA',
    ])
    def test_cases_for_key_type_not_supported(
            self,
            kt: crypto_knowledge.KeyType,
            param: Optional[int] = None,
            param_descr: str = '',
    ) -> Iterator[test_case.TestCase]:
        """Return test cases exercising key creation when the given type is unsupported.

        If param is present and not None, emit test cases conditioned on this
        parameter not being supported. If it is absent or None, emit test cases
        conditioned on the base type not being supported.
        """
        if kt.name in self.ALWAYS_SUPPORTED:
            # Don't generate test cases for key types that are always supported.
            # They would be skipped in all configurations, which is noise.
            return
        import_dependencies = [('!' if param is None else '') +
                               psa_want_symbol(kt.name)]
        if kt.params is not None:
            import_dependencies += [('!' if param == i else '') +
                                    psa_want_symbol(sym)
                                    for i, sym in enumerate(kt.params)]
        if kt.name.endswith('_PUBLIC_KEY'):
            generate_dependencies = []
        else:
            generate_dependencies = import_dependencies
        for bits in kt.sizes_to_test():
            yield test_case_for_key_type_not_supported(
                'import', kt.expression, bits,
                finish_family_dependencies(import_dependencies, bits),
                test_case.hex_string(kt.key_material(bits)),
                param_descr=param_descr,
            )
            if not generate_dependencies and param is not None:
                # If generation is impossible for this key type, rather than
                # supported or not depending on implementation capabilities,
                # only generate the test case once.
                continue
            yield test_case_for_key_type_not_supported(
                'generate', kt.expression, bits,
                finish_family_dependencies(generate_dependencies, bits),
                str(bits),
                param_descr=param_descr,
            )
            # To be added: derive

    def test_cases_for_not_supported(self) -> Iterator[test_case.TestCase]:
        """Generate test cases that exercise the creation of keys of unsupported types."""
        for key_type in sorted(self.constructors.key_types):
            kt = crypto_knowledge.KeyType(key_type)
            yield from self.test_cases_for_key_type_not_supported(kt)
        for curve_family in sorted(self.constructors.ecc_curves):
            for constr in ('PSA_KEY_TYPE_ECC_KEY_PAIR',
                           'PSA_KEY_TYPE_ECC_PUBLIC_KEY'):
                kt = crypto_knowledge.KeyType(constr, [curve_family])
                yield from self.test_cases_for_key_type_not_supported(
                    kt, param_descr='type')
                yield from self.test_cases_for_key_type_not_supported(
                    kt, 0, param_descr='curve')

    def generate_not_supported(self) -> None:
        """Generate a test case file covering the creation of keys of unsupported types."""
        # To be added: parametrized key types FFDH
        self.write_test_data_file(
            'test_suite_psa_crypto_not_supported.generated',
            self.test_cases_for_not_supported())

    @staticmethod
    def keys_for_storage_format(
            version: int
    ) -> Iterator[Tuple[psa_storage.Key, str]]:
        """WIP"""
        yield psa_storage.Key(version=version,
                              id=1, lifetime=0x00000001,
                              type=0x2400, bits=128,
                              usage=0x00000300, alg=0x05500200, alg2=0x04c01000,
                              material=b'@ABCDEFGHIJKLMNO'), 'foo'

    @staticmethod
    def storage_test_case(key: psa_storage.Key,
                          name: str, forward: bool) -> test_case.TestCase:
        """Construct a storage format test case for the given key.

        If ``forward`` is true, generate a forward compatibility test case:
        create a key and validate that it has the expected representation.
        Otherwise generate a backward compatibility test case: inject the
        key representation into storage and validate that it can be read
        correctly.
        """
        verb = 'save' if forward else 'read'
        tc = test_case.TestCase()
        tc.set_description('PSA storage {}: {}'.format(verb, name))
        dependencies = automatic_dependencies(
            key.lifetime.string, key.type.string,
            key.usage.string, key.alg.string, key.alg2.string,
        )
        tc.set_dependencies(dependencies)
        tc.set_function('key_storage_' + verb)
        if forward:
            extra_arguments = []
        else:
            # Some test keys have the RAW_DATA type and attributes that don't
            # necessarily make sense. We do this to validate numerical
            # encodings of the attributes.
            # Raw data keys have no useful exercise anyway so there is no
            # loss of test coverage.
            exercise = key.type.string != 'PSA_KEY_TYPE_RAW_DATA'
            extra_arguments = ['1' if exercise else '0']
        tc.set_arguments([key.lifetime.string,
                          key.type.string, str(key.bits),
                          key.usage.string, key.alg.string, key.alg2.string,
                          '"' + key.material.hex() + '"',
                          '"' + key.hex() + '"',
                          *extra_arguments])
        return tc

    def generate_storage_format(self) -> None:
        # First construct all the keys for which we want to generate test
        # cases, then construct the corresponding test cases. This way the
        # psa_storage module only needs to obtain numerical values once
        # (this requires compiling and running a C program, so it's slow).
        keys_v0 = list(self.keys_for_storage_format(0))
        self.write_test_data_file(
            'test_suite_psa_crypto_storage_format.v0',
            [self.storage_test_case(key, name, False)
             for key, name in keys_v0])
        self.write_test_data_file(
            'test_suite_psa_crypto_storage_format.current',
            [self.storage_test_case(key, name, True)
             for key, name in keys_v0])

    def generate_all(self):
        # When adding (or renaming or removing) generated files, remember
        # to update check-generated-files.sh.
        self.generate_not_supported()
        self.generate_storage_format()

def main(args):
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.parse_args(args)
    generator = TestGenerator(options)
    generator.generate_all()

if __name__ == '__main__':
    main(sys.argv[1:])
