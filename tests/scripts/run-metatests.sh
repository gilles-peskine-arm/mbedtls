#!/bin/sh

help () {
    cat <<EOF
Usage: $0 [OPTION] [PLATFORM]...
Run all the metatests whose platform matches any of the given PLATFORM.
A PLATFORM can contain shell wildcards.

  -l  List the available metatests, don't run them.
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

set -e -u

if [ -d programs ]; then
    METATEST_PROGRAM=programs/test/metatest
elif [ -d ../programs ]; then
    METATEST_PROGRAM=../programs/test/metatest
elif [ -d ../../programs ]; then
    METATEST_PROGRAM=../../programs/test/metatest
else
    echo >&2 "$0: FATAL: programs/test/metatest not found"
    exit 120
fi

LIST_ONLY=
while getopts hl OPTLET; do
    case $OPTLET in
        h) help; exit;;
        l) LIST_ONLY=1;;
        \?) help >&2; exit 120;;
    esac
done
shift $((OPTIND - 1))

list_matches () {
    while read name platform junk; do
        for pattern; do
            case $platform in
                $pattern) echo "$name"; break;;
            esac
        done
    done
}

count=0
errors=0
run_metatest () {
    ret=0
    "$METATEST_PROGRAM" "$1" || ret=$?
    if [ $ret -eq 0 ]; then
        echo >&2 "$0: Unexpected success: $1"
        errors=$((errors + 1))
    fi
    count=$((count + 1))
}

# Don't pipe the output of metatest so that if it fails, this script exits
# immediately with a failure status.
full_list=$("$METATEST_PROGRAM" list)
matching_list=$(printf '%s\n' "$full_list" | list_matches "$@")

if [ -n "$LIST_ONLY" ]; then
    printf '%s\n' $matching_list
    exit
fi

for name in $matching_list; do
    run_metatest "$name"
done

if [ $errors -eq 0 ]; then
    echo "Ran $count metatests, all good."
    exit 0
else
    echo "Ran $count metatests, $errors unexpected successes."
    exit 1
fi
