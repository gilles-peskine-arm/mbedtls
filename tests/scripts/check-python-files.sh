#! /usr/bin/env sh

# This file is part of Mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, Arm Limited, All Rights Reserved
#
# Purpose:
#
# Run 'pylint' on Python files for programming errors and helps enforcing
# PEP8 coding standards.

# Find the installed version of Pylint. Installed as a distro package this can
# be pylint3 and as a PEP egg, pylint. We prefer pylint over pylint3 if pylint
# is acceptable.
case $(pylint --version 2>/dev/null) in
  *'Python 3'*)
    PYLINT=pylint;;
  *)
    # Either pylint is not installed or it's for Python 2
    if type pylint3 >/dev/null 2>/dev/null; then
        PYLINT=pylint3
    else
        echo 'Pylint was not found.'
        exit 1
    fi;;
esac

$PYLINT -j 2 scripts/*.py tests/scripts/*.py
