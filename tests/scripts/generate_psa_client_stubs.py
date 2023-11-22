#!/usr/bin/env python3
"""Generate PSA crypto client stubs that call PSA IPC.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
from typing import Iterable, List, Optional, Tuple

import scripts_path #pylint: disable=unused-import
from mbedtls_dev import c_wrapper_generator
from mbedtls_dev import typing_util

import generate_psa_wrappers


class PSAClientCallVectors:
    """In and out vectors for a PSA call."""
    #pylint: disable=too-few-public-methods

    def __init__(self) -> None:
        # In/out vectors: list of (pointer, length)
        self.in_vecs = [] #type: List[Tuple[str, str]]
        self.out_vecs = [] #type: List[Tuple[str, str]]
        # Out vectors: argument where the length is returned
        self.out_lengths = [] #type: List[Optional[str]]
        # In/out data: list of (field_name, argument)
        self.in_data = [] #type: List[Tuple[str, str]]
        self.out_data = [] #type: List[Tuple[str, str]]

    def process_arguments(self,
                          arguments: Iterable[Tuple[c_wrapper_generator.ArgumentInfo, str]]
                          ) -> None:
        """Populate the vectors based on the function arguments.

        Create an input_vector for each input buffer and an output vector
        for each output buffer.
        If there are non-buffer inputs, add an input vector containing
        the local variable `inputs`.
        If there are non-buffer outputs, add an input vector containing
        the local variable `outputs`.
        """
        #pylint: disable=too-many-branches
        # Make our own copy that can be accessed non-sequentially
        args = list(arguments)
        skip = 0
        for num in range(len(args)): #pylint: disable=consider-using-enumerate
            if skip:
                skip -= 1
                continue
            arg, name = args[num]
            if len(args) > num + 1:
                next_arg, next_name = args[num + 1]
            else:
                next_arg, next_name = None, 'oops'
            if len(args) > num + 2:
                next2_arg, next2_name = args[num + 2]
            else:
                next2_arg, next2_name = None, 'oops'
            if arg.type == 'const uint8_t *' and \
               next_arg is not None and \
               next_arg.type == 'size_t' and \
               next_arg.suffix == '':
                self.in_vecs.append((name, next_name))
                skip = 1
            elif arg.type == 'uint8_t *' and \
               next_arg is not None and \
               next_arg.type == 'size_t' and \
               next_arg.suffix == '':
                self.out_vecs.append((name, next_name))
                skip = 1
                if next2_arg is not None and \
                   next2_arg.type == 'size_t *' and \
                   next2_arg.suffix == '':
                    self.out_lengths.append(next2_name)
                    skip = 2
                else:
                    self.out_lengths.append(None)
            elif '*' in arg.type:
                self.out_data.append(('TODO', name))
            else:
                self.in_data.append(('TODO', name))
        if self.in_data:
            self.in_vecs = [('inputs', 'sizeof(inputs)')] + self.in_vecs
        if self.out_data:
            self.out_vecs = [('outputs', 'sizeof(outputs)')] + self.out_vecs

    def write_data_inputs(self, out: typing_util.Writable) -> None:
        """Write code to copy the non-buffer inputs."""
        for field, src in self.in_data:
            out.write('    inputs.{field} = {src};\n'
                      .format(field=field, src=src))

    def write_data_outputs(self, out: typing_util.Writable) -> None:
        """Write code to copy the non-buffer outputs."""
        for field, dest in self.out_data:
            out.write('    *{dest} = outputs.{field};\n'
                      .format(field=field, dest=dest))

    def write_length_outputs(self, out: typing_util.Writable) -> None:
        """Write code to copy the output lengths."""
        for i, dest in enumerate(self.out_lengths):
            if dest is None:
                continue
            out.write('    *{dest} = out_vecs[{i}];\n'
                      .format(i=i, dest=dest))


class PSAClientGenerator(generate_psa_wrappers.PSAWrapperGenerator):
    """Generate a C source file containing client stub functions for PSA Crypto API calls."""

    CPP_GUARDS = 'defined(MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(MBEDTLS_PSA_CRYPTO_C)'
    WRAPPER_NAME_PREFIX = ''
    WRAPPER_NAME_SUFFIX = ''

    def _write_prologue(self, out: typing_util.Writable, header: bool) -> None:
        super()._write_prologue(out, header)
        out.write("""\
#include <psa/client.h>
""")

    def _skip_function(self, function: c_wrapper_generator.FunctionInfo) -> bool:
        if super()._skip_function(function):
            return True
        if function == 'psa_crypto_init':
            return True
        return False

    @staticmethod
    def _write_vec_def(out: typing_util.Writable,
                       direction: str,
                       vecs: List[Tuple[str, str]]) -> None:
        """Write the definition of in_vecs or out_vecs."""
        if vecs:
            out.write('    psa_{dir}vec {dir}_vecs[{len}] = {{\n'
                      .format(dir=direction, len=len(vecs)))
            for vec in vecs:
                out.write('        {{ {}, {} }},\n'.format(vec[0], vec[1]))
            out.write('    };\n')
        else:
            out.write('    psa_{dir}vec *{dir}_vecs = NULL;\n'
                      .format(dir=direction))

    def _write_function_body(self, out: typing_util.Writable,
                             function: c_wrapper_generator.FunctionInfo,
                             argument_names: List[str]) -> None:
        """Write a psa_call remote procedure call."""
        vectors = PSAClientCallVectors()
        vectors.process_arguments(zip(function.arguments, argument_names))
        if vectors.in_data:
            out.write('    {} inputs;\n'.format('TODO'))
            out.write('    memset(&inputs, 0, sizeof(inputs));\n')
            vectors.write_data_inputs(out)
        if vectors.out_data:
            out.write('    {} outputs;\n'.format('TODO'))
            out.write('    memset(&outputs, 0, sizeof(outputs));\n')
        self._write_vec_def(out, 'in', vectors.in_vecs)
        self._write_vec_def(out, 'out', vectors.out_vecs)
        out.write("""\
    psa_status_t status = psa_call(mbedtls_test_psa_crypto_client_handle,
                                   MBEDTLS_PSA_FUNCTION_{},
                                   in_vecs, {},
                                   out_vecs, {});
"""
                  .format(function.name.upper(),
                          len(vectors.in_vecs), len(vectors.out_vecs)))
        vectors.write_length_outputs(out)
        vectors.write_data_outputs(out)
        out.write('    return status;\n')


DEFAULT_C_OUTPUT_FILE_NAME = 'tests/src/psa_client_wrappers.c'
DEFAULT_H_OUTPUT_FILE_NAME = 'tests/include/test/psa_client_wrappers.h'

def main() -> None:
    parser = argparse.ArgumentParser(description=globals()['__doc__'])
    parser.add_argument('--output-c',
                        metavar='FILENAME',
                        default=DEFAULT_C_OUTPUT_FILE_NAME,
                        help=('Output .c file path (default: {}; skip .c output if empty)'
                              .format(DEFAULT_C_OUTPUT_FILE_NAME)))
    parser.add_argument('--output-h',
                        metavar='FILENAME',
                        default=DEFAULT_H_OUTPUT_FILE_NAME,
                        help=('Output .h file path (default: {}; skip .h output if empty)'
                              .format(DEFAULT_H_OUTPUT_FILE_NAME)))
    options = parser.parse_args()
    generator = PSAClientGenerator()
    generator.gather_data()
    if options.output_h:
        generator.write_h_file(options.output_h)
    if options.output_c:
        generator.write_c_file(options.output_c)

if __name__ == '__main__':
    main()
