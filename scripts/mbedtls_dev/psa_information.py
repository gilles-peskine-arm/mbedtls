"""Collect information about PSA cryptographic mechanisms.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later


import re
from typing import Dict, FrozenSet, List, Optional

from . import macro_collector
from . import test_case


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

SYMBOLS_WITHOUT_DEPENDENCY = frozenset([
    'PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG', # modifier, only in policies
    'PSA_ALG_AEAD_WITH_SHORTENED_TAG', # modifier
    'PSA_ALG_ANY_HASH', # only in policies
    'PSA_ALG_AT_LEAST_THIS_LENGTH_MAC', # modifier, only in policies
    'PSA_ALG_KEY_AGREEMENT', # chaining
    'PSA_ALG_TRUNCATED_MAC', # modifier
])

def automatic_dependencies(*expressions: str) -> List[str]:
    """Infer dependencies of a test case by looking for PSA_xxx symbols.
    The arguments are strings which should be C expressions. Do not use
    string literals or comments as this function is not smart enough to
    skip them.
    """
    used = set()
    for expr in expressions:
        used.update(re.findall(r'PSA_(?:ALG|ECC_FAMILY|KEY_TYPE)_\w+', expr))
    used.difference_update(SYMBOLS_WITHOUT_DEPENDENCY)
    return sorted(psa_want_symbol(name) for name in used)


class Information:
    """Gather information about PSA constructors."""

    def __init__(self) -> None:
        self.constructors = self.read_psa_interface()

    @staticmethod
    def remove_unwanted_macros(
            constructors: macro_collector.PSAMacroEnumerator
    ) -> None:
        # Mbed TLS doesn't support finite-field DH yet and will not support
        # finite-field DSA. Don't attempt to generate any related test case.
        constructors.key_types.discard('PSA_KEY_TYPE_DH_KEY_PAIR')
        constructors.key_types.discard('PSA_KEY_TYPE_DH_PUBLIC_KEY')
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_KEY_PAIR')
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_PUBLIC_KEY')

    def read_psa_interface(self) -> macro_collector.PSAMacroEnumerator:
        """Return the list of known key types, algorithms, etc."""
        constructors = macro_collector.InputsForTest()
        header_file_names = ['include/psa/crypto_values.h',
                             'include/psa/crypto_extra.h']
        test_suites = ['tests/suites/test_suite_psa_crypto_metadata.data']
        for header_file_name in header_file_names:
            constructors.parse_header(header_file_name)
        for test_cases in test_suites:
            constructors.parse_test_cases(test_cases)
        self.remove_unwanted_macros(constructors)
        constructors.gather_arguments()
        return constructors


class PSATestCase(test_case.TestCase):
    """A PSA test case with automatically inferred dependencies."""

    _implemented_dependencies = None #type: FrozenSet[str]
    DEPENDENCIES_FILENAME = 'include/psa/crypto_config.h'
    WANT_SYMBOL_RE = re.compile(r'\bPSA_WANT_\w+\b')
    @classmethod
    def read_implemented_dependencies(cls) -> FrozenSet[str]:
        with open(cls.DEPENDENCIES_FILENAME) as dependencies_file:
            cls._implemented_dependencies = frozenset(
                symbol
                for line in dependencies_file
                for symbol in cls.WANT_SYMBOL_RE.findall(line))

    WANT_DEPENDENCY_RE = re.compile(r'!?(PSA_WANT_\w+)\Z')
    def is_dependency_implemented(self, dependency: str) -> bool:
        self.read_implemented_dependencies()
        m = self.WANT_DEPENDENCY_RE.match(dependency)
        if not m:
            # Not a PSA_WANT_xxx dependency, so assume that it's implemented.
            return True
        want_symbol = m.group(1)
        return want_symbol in self._implemented_dependencies

    def __init__(self) -> None:
        super().__init__()
        if self._implemented_dependencies is None:
            self.read_implemented_dependencies()
        self.key_bits = None #type: Optional[int]

    def set_key_bits(self, key_bits: Optional[int]) -> None:
        """Use the given key size for automatic dependency generation.

        This is only relevant for ECC and DH keys. For other key types,
        this information is ignored.
        """
        self.key_bits = key_bits

    def set_arguments(self, arguments: List[str]) -> None:
        self.arguments = arguments
        dependencies = automatic_dependencies(*arguments)
        if self.key_bits is not None:
            dependencies = finish_family_dependencies(dependencies, self.key_bits)
        self.dependencies += dependencies
        not_implemented = [dep
                           for dep in dependencies
                           if (dep.startswith('PSA_WANT_') and
                               dep not in self._implemented_dependencies)]
        if not_implemented:
            #self.omit_because('not implemented: ' + ' '.join(not_implemented))
            self.add_comment('not implemented: ' + ' '.join(not_implemented))
            self.dependencies.append('DEPENDENCY_NOT_IMPLEMENTED_YET')
