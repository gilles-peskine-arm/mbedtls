#!/usr/bin/env python3
"""Report on uses of legacy APIs.

This script uses the clang python bindings (``pip3 install --user clang``).

This script only works on code that compiles. If there are any errors,
this script will just return garbage data (typically missing fields, or
having 0 values everywhere). The most common cause of failure is missing
include directories, either for the code you're analyzing or for the
standard library when cross-compiling.
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
import collections
import re
import sys
import typing
from typing import Dict, Iterator, List, Optional, Tuple

import clang.cindex #type: ignore
from clang.cindex import Cursor, SourceLocation, TranslationUnit
from clang.cindex import CursorKind, TypeKind

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework import typing_util


class SanityCheck(Exception):
    def __init__(self, msg: str) -> None:
        super().__init__('Sanity check failed: ' + msg +
                         '\nThis likely indicates a compilation error.' +
                         '\nMaybe a missing include directory (-I)?')


class Ast:
    """Abstract representation of the source code."""

    def __init__(self, options) -> None:
        """Prepare for analysis of C source files."""
        if options.clang_library_file:
            clang.cindex.Config.set_library_file(options.clang_library_file)
        self.parse_options = []
        if options.target:
            self.parse_options += ['-target', options.target]
        for d in options.include:
            self.parse_options.append('-I' + d)
        for d in options.define:
            self.parse_options.append('-D' + d)
        self.index = clang.cindex.Index.create()
        self.files = {}

    def load(self, *filenames: str) -> None:
        """Load the AST of the given source files."""
        for filename in filenames:
            self.files[filename] = self.index.parse(filename,
                                                    self.parse_options)

    def in_interesting_file(self, location: SourceLocation) -> bool:
        """Whether the given location is in a file that should be analyzed."""
        if not hasattr(location.file, 'name'):
            # Some artificial nodes have associated no file name.
            # Let's hope they're not important.
            return False
        return location.file.name in self.files

    def read_node(self, node: Cursor) -> None:
        """Collect information from the given node."""
        raise NotImplementedError

    def read_files(self, filenames: List[str]) -> None:
        """Parse and collect information from the given C source files."""
        self.load(*filenames)
        for filename in filenames:
            for node in self.files[filename].cursor.walk_preorder():
                if not self.in_interesting_file(node.location):
                    continue
                self.read_node(node)

    def sanity_check_failed(self, log: Optional[typing_util.Writable],
                            fmt: str, *args, **kwargs) -> None:
        """Signal that the data looks wrong.

        If `log` is `None`, signaling means to raise an exception explaining
        the first failure encountered. Otherwise signaling means calling
        `log.write` with a message for each failure.
        """
        #pylint: disable=no-self-use,no-else-raise
        msg = fmt.format(*args, **kwargs)
        if log is None:
            raise SanityCheck(msg)
        else:
            log.write('Warning: ' + msg + '\n')


class UnstableTypes(Ast):

    def __init__(self, options) -> None:
        super().__init__(options)
        self.uses_of_unstable_types = {} \
            #type: Dict[typing.Hashable, Tuple[clang.cindex.Type, SourceLocation, str]]

    @staticmethod
    def location_key(location: SourceLocation) -> Tuple[str, int, int]:
        return (location.file.name, location.line, location.column)

    @staticmethod
    def get_underlying_type(type_: clang.cindex.Type) -> Optional[clang.cindex.Type]:
        """Strip off one level of type indirection.

        Return None if the type is as primitive as can be.
        """
        if hasattr(type_, 'get_canonical'):
            lower = type_.get_canonical()
            if lower != type_:
                return lower
        if type_.kind == TypeKind.POINTER:
            return type_.get_pointee()
        if hasattr(type_, 'underlying_typedef_type'):
            return type_.underlying_typedef_type
        return None

    def get_type_qualified_core(self, type_: clang.cindex.Type) -> str:
        """Get the core of a type, without typedefs or pointers."""
        core = type_
        lower = type_ # type: Optional[clang.cindex.Type]
        while lower:
            core, lower = lower, self.get_underlying_type(core)
        return core

    QUALIFIERS_RE = re.compile(r'.* ')
    def get_type_core(self, type_: clang.cindex.Type) -> str:
        """Get the base name of a type, without typedefs, qualifiers or pointers."""
        # There's no API function to remove qualifiers from a type,
        # so do it textually. Remove 'const', 'restrict', etc.
        # Also remove 'struct', so we'll get the struct name from struct
        # definitions.
        core = self.get_type_qualified_core(type_)
        return re.sub(self.QUALIFIERS_RE, r'', core.spelling)

    @staticmethod
    def get_base_type(type_: clang.cindex.Type) -> Optional[clang.cindex.Type]:
        """Return the base of the type, without pointers.

        Typedefs are not expanded, unlike get_type_qualified_core().
        """
        while type_.kind == TypeKind.POINTER:
            type_ = type_.get_pointee()
        return type_

    def sanity_checks(self, log: Optional[typing_util.Writable]) -> None:
        """If the data looks wrong, signal it.

        See `sanity_check_failed()` regarding how signaling works.
        """
        pass #TODO

    HEADER_UNDER_INCLUDE_RE = re.compile(r'/include/(.*)\Z', re.S)

    PUBLIC_HEADERS = frozenset([
        'mbedtls/asn1.h',
        'mbedtls/platform.h',
        'mbedtls/platform_time.h',
        'mbedtls/platform_util.h',
    ])

    def is_private_header(self, filename: str) -> bool:
        """Whether the given header path is a private header."""
        if '/drivers/' not in filename:
            return False
        m = re.search(self.HEADER_UNDER_INCLUDE_RE, filename)
        assert m is not None
        included_as = m.group(1)
        if included_as in self.PUBLIC_HEADERS:
            return False
        return True

    NOT_ACTUALLY_PRIVATE_TYPES = frozenset([
        'mbedtls_md_type_t',
        'mbedtls_pem_context',
        'mbedtls_pk_context',
    ])

    def read_use_of_type(self,
                         type_: clang.cindex.Type,
                         location: SourceLocation,
                         descriptor: str) -> None:
        """Process a mention of a type in a public header."""
        type_base = self.get_base_type(type_)
        declaration_location = type_base.get_declaration().location
        if declaration_location.file is None:
            # Built-in type, e.g. int
            return
        if type_base.spelling in self.NOT_ACTUALLY_PRIVATE_TYPES:
            return
        if not self.is_private_header(declaration_location.file.name):
            return
        #print(descriptor, type_base.spelling, declaration_location.file.name)
        key = self.location_key(location)
        self.uses_of_unstable_types[key] = (type_, location, descriptor)

    @staticmethod
    def get_all_children(node: Cursor) -> Iterator[Cursor]:
        yield from node.get_children()
        if hasattr(node, 'get_arguments'):
            yield from node.get_arguments()

    def read_node(self, node: Cursor) -> None:
        """Collect information from the given node."""
        # In public headers, collect function argument types and return types
        # where the type is defined in a private header.
        if node.kind == CursorKind.FUNCTION_DECL:
            for num, argument in enumerate(node.get_arguments(), 1):
                self.read_use_of_type(argument.type,
                                      argument.location,
                                      f'{node.spelling}#{num}={argument.spelling}')
            self.read_use_of_type(node.result_type,
                                  node.location,
                                  f'{node.spelling}#return')

    def run_analysis(self, files: List[str],
                     log: Optional[typing_util.Writable] = None) -> None:
        """Run analyses on the specified files.

        Pass `log` to `sanity_checks`.
        """
        self.read_files(files)
        self.sanity_checks(log)

    def report(self, out: typing_util.Writable) -> None:
        """Report on the use of unstable types."""
        for (type_, location, descriptor) in self.uses_of_unstable_types.values():
            print(f'{location.file.name}:{location.line}:{location.column}: '
                  f'{descriptor}: {type_.spelling}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang-library-file',
                        help="Alternative location of libclang.so")
    parser.add_argument('--define', '-D',
                        action='append',
                        default=[],
                        help="Additional C preprocessor definition")
    parser.add_argument('--include', '-I',
                        action='append',
                        default=[],
                        help="Directory to add to the header include path")
    parser.add_argument('--no-csv-header',
                        dest='csv_header', default=True, action='store_false',
                        help="Omit the CSV header from the output")
    parser.add_argument('--no-sanity-checks',
                        dest='sanity_checks', default=True, action='store_false',
                        help="Bypass sanity checks, print output even if it's suspicious")
    parser.add_argument('--target', '-t',
                        help="Target triple to build for (default: native build)")
    parser.add_argument('files', metavar='FILE', nargs='*',
                        help="Source files to analyze")
    options = parser.parse_args()
    ast = UnstableTypes(options)
    if options.sanity_checks:
        sanity_log = None
    else:
        sanity_log = sys.stderr
    ast.run_analysis(options.files, log=sanity_log)
    ast.report(sys.stdout)

if __name__ == '__main__':
    main()
