#!/bin/sh

# Measure heap usage (and performance) of ECC operations with various values of
# the relevant tunable compile-time parameters.
#
# Usage (preferably on a 32-bit platform):
# cmake -D CMAKE_BUILD_TYPE=Release .
# scripts/ecc-heap.sh | tee ecc-heap.log

. "$(dirname -- "$0")/lib.sh" || exit 125
if [ -e "$CONFIG_H" ]; then
    save_config
fi

if grep -q CMAKE Makefile >/dev/null; then
    rebuild () {
        make benchmark
    }
else
    rebuild () {
        make -C programs test/benchmark
    }
fi

cat << EOF >$CONFIG_H
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_MEMORY_DEBUG

#define MBEDTLS_TIMING_C

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_C

#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED

#include "check_config.h"

//#define MBEDTLS_ECP_WINDOW_SIZE            6
//#define MBEDTLS_ECP_FIXED_POINT_OPTIM      1
EOF

for F in 0 1; do
    for W in 2 3 4 5 6; do
        scripts/config.pl set MBEDTLS_ECP_WINDOW_SIZE $W
        scripts/config.pl set MBEDTLS_ECP_FIXED_POINT_OPTIM $F
        rebuild >/dev/null 2>&1
        echo "fixed point optim = $F, max window size = $W"
        echo "--------------------------------------------"
        programs/test/benchmark
    done
done
