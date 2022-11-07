"""Common features for bignum in test generation framework."""
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

import itertools
import typing

from abc import abstractmethod
from typing import Iterator, List, Tuple, TypeVar

T = TypeVar('T') #pylint: disable=invalid-name

def invmod(a: int, n: int) -> int:
    """Return inverse of a to modulo n.

    Equivalent to pow(a, -1, n) in Python 3.8+. Implementation is equivalent
    to long_invmod() in CPython.
    """
    b, c = 1, 0
    while n:
        q, r = divmod(a, n)
        a, b, c, n = n, c, b - q*c, r
    # at this point a is the gcd of the original inputs
    if a == 1:
        return b
    raise ValueError("Not invertible")

def hex_to_int(val: str) -> int:
    return int(val, 16) if val else 0

def quote_str(val) -> str:
    return "\"{}\"".format(val)

def bound_mpi(val: int, bits_in_limb: int) -> int:
    """First number exceeding number of limbs needed for given input value."""
    return bound_mpi_limbs(limbs_mpi(val, bits_in_limb), bits_in_limb)

def bound_mpi_limbs(limbs: int, bits_in_limb: int) -> int:
    """First number exceeding maximum of given number of limbs."""
    bits = bits_in_limb * limbs
    return 1 << bits

def limbs_mpi(val: int, bits_in_limb: int) -> int:
    """Return the number of limbs required to store value."""
    return (val.bit_length() + bits_in_limb - 1) // bits_in_limb

def combination_pairs(values: List[T]) -> List[Tuple[T, T]]:
    """Return all pair combinations from input values.

    The return value is cast, as older versions of mypy are unable to derive
    the specific type returned by itertools.combinations_with_replacement.
    """
    return typing.cast(
        List[Tuple[T, T]],
        list(itertools.combinations_with_replacement(values, 2))
    )


class OperationCommon:
    """Common features for bignum binary operations.

    This adds functionality common in binary operation tests.

    Attributes:
        symbol: Symbol to use for the operation in case description.
        input_values: List of values to use as test case inputs. These are
            combined to produce pairs of values.
        input_cases: List of tuples containing pairs of test case inputs. This
            can be used to implement specific pairs of inputs.
        unique_combinations_only: Boolean to select if test case combinations
            must be unique. If True, only A,B or B,A would be included as a test
            case. If False, both A,B and B,A would be included.
    """
    symbol = ""
    input_values = [] # type: List[str]
    input_cases = [] # type: List[Tuple[str, str]]
    unique_combinations_only = True

    def __init__(self, val_a: str, val_b: str) -> None:
        self.arg_a = val_a
        self.arg_b = val_b
        self.int_a = hex_to_int(val_a)
        self.int_b = hex_to_int(val_b)

    def arguments(self) -> List[str]:
        return [
            quote_str(self.arg_a), quote_str(self.arg_b)
        ] + self.result()

    @abstractmethod
    def result(self) -> List[str]:
        """Get the result of the operation.

        This could be calculated during initialization and stored as `_result`
        and then returned, or calculated when the method is called.
        """
        raise NotImplementedError

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, str]]:
        """Generator to yield pairs of inputs.

        Combinations are first generated from all input values, and then
        specific cases provided.
        """
        if cls.unique_combinations_only:
            yield from combination_pairs(cls.input_values)
        else:
            yield from (
                (a, b)
                for a in cls.input_values
                for b in cls.input_values
            )
        yield from cls.input_cases

# BEGIN MERGE SLOT 1

# A helper function to generate test data.
#
# Commented out as it uses pycryptodome:
#   from Crypto.Util.number import isPrime, getPrime
# (pycryptodome is only a maintainer requirement and we don't want the test
# generation to depend on it.)
#
# def gen_safe_prime(bits, seed):
#     rng = random.Random()
#     # We want reproducability across python versions
#     rng.seed(seed, version=2)
#     while True:
#         prime = 2*getPrime(bits-1, rng.randbytes)+1
#         if isPrime(prime, 1e-30):
#             return prime

class ModOperationCommon:
    """Common features for bignum modular operations.

    This adds functionality common in modular operation tests. This includes
    generation of case descriptions, using descriptions of values and symbols
    to represent the operation or result.

    Attributes:
        symbol: Symbol used for the operation in case description.
        input_1st_operands: List of values to use as first operands.
        input_2nd_operands: List of values to use as second operands.
        input_moduli: List of moduli this to use in test cases. These are
            combined with the operands to produce the test cases.
        input_cases: List of tuples containing triplets (operand 1, operand 2,
            modulus) of test case inputs. This can be used to implement
            specific combination of inputs.
    """
    symbol = ""
    input_1st_operands = [] # type: List[Tuple[str, str]]
    input_2nd_operands = [] # type: List[Tuple[str, str]]
    input_moduli = [] # type: List[Tuple[str, str]]

    def __init__(self, a: Tuple[str, str], b: Tuple[str, str],
                 m: Tuple[str, str]) -> None:
        self.arg_a = a[0]
        self.arg_b = b[0]
        self.arg_m = m[0]
        self.desc_a = a[1]
        self.desc_b = b[1]
        self.desc_m = m[1]
        self.int_a = hex_to_int(self.arg_a)
        self.int_b = hex_to_int(self.arg_b)
        self.int_m = hex_to_int(self.arg_m)
        if self.int_a >= self.int_m or self.int_b >= self.int_m:
            raise ValueError("Operand(s) are not canonical")

    def arguments(self) -> List[str]:
        return [quote_str(self.arg_a), quote_str(self.arg_b),
                quote_str(self.arg_m), self.result()]

    def generate_description(self) -> str:
        """Generate a description for the test case."""
        return "{} {} {} mod {}".format(
            self.value_description(self.int_a, self.desc_a),
            self.symbol,
            self.value_description(self.int_b, self.desc_b),
            self.value_description(self.int_m, self.desc_m)
        )

    @abstractmethod
    def result(self) -> str:
        """Get the result of the operation.

        This could be calculated during initialization and stored as `_result`
        and then returned, or calculated when the method is called.
        """
        raise NotImplementedError

    @staticmethod
    def value_description(val, desc) -> str:
        """Generate a description of the argument val.

        This produces a simple description of the value, which is used in test
        case naming to add context.
        """
        bit_length = val.bit_length()
        if bit_length <= 16:
            return '{} ({})'.format(val, desc)
        else:
            return '{} bit {}'.format(bit_length, desc)

    @classmethod
    def get_value_triplets(cls) -> Iterator[
            Tuple[Tuple[str, str], Tuple[str, str], Tuple[str, str]]]:
        for a in cls.input_1st_operands:
            for b in cls.input_2nd_operands:
                for m in cls.input_moduli:
                    yield (a, b, m)


# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

# END MERGE SLOT 3

# BEGIN MERGE SLOT 4

# END MERGE SLOT 4

# BEGIN MERGE SLOT 5

# END MERGE SLOT 5

# BEGIN MERGE SLOT 6

# END MERGE SLOT 6

# BEGIN MERGE SLOT 7

# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
