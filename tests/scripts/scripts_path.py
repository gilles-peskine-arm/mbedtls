"""Add our Python library directory to the module search path.

Usage:

    import scripts_path # pylint: disable=unused-import
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import os
import sys

_FRAMEWORK_DIR = os.getenv('MBEDTLS_FRAMEWORK')
if _FRAMEWORK_DIR is None:
    _FRAMEWORK_DIR = os.path.join(os.path.dirname(__file__),
                                  os.path.pardir, 'framework')
else:
    _FRAMEWORK_DIR = os.path.abspath(_FRAMEWORK_DIR)

sys.path.append(os.path.join(os.path.dirname(__file__),
                             os.path.pardir, os.path.pardir,
                             'scripts'))
sys.path.append(os.path.join(_FRAMEWORK_DIR, 'scripts'))
