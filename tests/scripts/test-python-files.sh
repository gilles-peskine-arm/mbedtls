#! /usr/bin/env sh

help () {
    cat <<EOF
Usage: $0
Run the unit tests in Python scripts.
Must be run from the Mbed TLS root.
EOF
}

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

set -eu

if [ $# -ge 1 ] && [ "$1" = "--help" ]; then
    help
    exit
fi

QUIET=
while getopts q OPTLET; do
    case $OPTLET in
        q) QUIET=1;;
    esac
done
shift $((OPTIND - 1))

if [ -n "${PYTHON:-}" ]; then
    : # use $PYTHON from the environment
elif type python3 >/dev/null 2>/dev/null; then
    PYTHON=python3
else
    PYTHON=python
fi

failures=0
total=0

run_python () {
    total=$((total + 1))
    "$PYTHON" "$@" 2>&1 || failures=$((failures + 1))
}

# Look for Python modules that import the unittest module, and run their
# tests. This works better than `python -m unittest discover`, which has
# inferior feedback (it doesn't print the module name) and could easily
# do nothing and print "Ran 0 tests" without anyone noticing.
for script in $(grep -l '^import unittest' \
                     scripts/*.py \
                     scripts/mbedtls_dev/*.py \
                     tests/scripts/*.py\
               ); do
    echo "#### $script ####"
    run_python -m unittest "${script}"
done

# generate_test_code has a separate script for unit tests.
echo "#### tests/scripts/generate_test_code.py ####"
run_python tests/scripts/test_generate_test_code.py

if [ $failures -ne 0 ]; then
    echo >&2 "$0: $failures/$total FAILED"
    exit 1
else
    echo "$0: $total/$total PASSED"
fi
