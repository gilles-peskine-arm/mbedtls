#!/bin/sh

help () {
    cat <<'EOF'
The purpose of this script is to catch unjustified dependencies on
legacy feature macros (MBEDTLS_xxx) in PSA tests. Generally speaking,
PSA test should use PSA feature macros (PSA_WANT_xxx, more rarely
MBEDTLS_PSA_xxx).

Most of the time, use of legacy MBEDTLS_xxx macros are mistakes, which
this component is meant to catch. However a few of them are justified,
mostly by the absence of a PSA equivalent, so this component includes a
list of expected exceptions.
EOF
}

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -eu

if [ $# -ne 0 ]; then
    if [ "$1" = "--help" ]; then
        help
        exit 0
    else
        echo >&2 "Usage: $0 [--help]"
        exit 120
    fi
fi

found="check-test-deps-found-$$"
expected="check-test-deps-expected-$$"

trap 'rm -f $found $expected' EXIT HUP INT TERM

# Find legacy dependencies in PSA tests
grep 'depends_on' \
    tests/suites/test_suite_psa*.data tests/suites/test_suite_psa*.function |
    grep -Eo '!?MBEDTLS_[^: ]*' |
    grep -v MBEDTLS_PSA_ |
    sort -u > $found

# Expected ones with justification - keep in sorted order by ASCII table!
rm -f $expected
# No PSA equivalent - WANT_KEY_TYPE_AES means all sizes
echo "!MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH" >> $expected
# No PSA equivalent - used to skip decryption tests in PSA-ECB, CBC/XTS/NIST_KW/DES
echo "!MBEDTLS_BLOCK_CIPHER_NO_DECRYPT" >> $expected
# This is used by import_rsa_made_up() in test_suite_psa_crypto in order
# to build a fake RSA key of the wanted size based on
# PSA_VENDOR_RSA_MAX_KEY_BITS. The legacy module is only used by
# the test code and that's probably the most convenient way of achieving
# the test's goal.
echo "MBEDTLS_ASN1_WRITE_C" >> $expected
# No PSA equivalent - we should probably have one in the future.
echo "MBEDTLS_ECP_RESTARTABLE" >> $expected
# No PSA equivalent - needed by some init tests
echo "MBEDTLS_ENTROPY_NV_SEED" >> $expected
# Used by two tests that are about an extension to the PSA standard;
# as such, no PSA equivalent.
echo "MBEDTLS_PEM_PARSE_C" >> $expected

# Compare reality with expectation.
# We want an exact match, to ensure the above list remains up-to-date.
#
# The output should be empty. When it's not:
# - Each '+' line is a macro that was found but not expected. You want to
# find where that macro occurs, and either replace it with PSA macros, or
# add it to the exceptions list above with a justification.
# - Each '-' line is a macro that was expected but not found; it means the
# exceptions list above should be updated by removing that macro.
diff -U0 $expected $found
