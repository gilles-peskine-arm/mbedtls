#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

import scripts_path # pylint: disable=unused-import
from mbedtls_framework.config_checks_generator import * \
    #pylint: disable=wildcard-import,unused-wildcard-import

class CryptoInternal(SubprojectInternal):
    SUBPROJECT = 'TF-PSA-Crypto'

class CryptoOption(SubprojectOption):
    SUBPROJECT = 'TF-PSA-Crypto'

MBEDTLS_CHECKS = BranchData(
    header_directory='library',
    header_prefix='mbedtls_',
    project_cpp_prefix='MBEDTLS',
    checkers=[
        CryptoInternal('MBEDTLS_MD5_C', 'PSA_WANT_ALG_MD5 in psa/crypto_config.h'),
        CryptoInternal('MBEDTLS_USE_PSA_CRYPTO', 'always on'),
        CryptoOption('MBEDTLS_BASE64_C'),
        Removed('MBEDTLS_KEY_EXCHANGE_RSA_ENABLED', '4.0'),
        Removed('MBEDTLS_PADLOCK_C', '4.0'),
    ],
)

if __name__ == '__main__':
    main(MBEDTLS_CHECKS)
