#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

import scripts_path # pylint: disable=unused-import
from mbedtls_framework import config_checks_generator

MBEDTLS_REMOVED_OPTIONS = config_checks_generator.BranchData(
    header_directory='library',
    header_prefix='mbedtls_',
    project_cpp_prefix='MBEDTLS',
    removed_options={
        'MBEDTLS_USE_PSA_CRYPTO': 'none (always on)',
    },
)

if __name__ == '__main__':
    config_checks_generator.main(MBEDTLS_REMOVED_OPTIONS)
