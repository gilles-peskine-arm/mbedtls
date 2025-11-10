# components-compiler.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Compiler Testing
################################################################

support_build_armcc () {
    armc6_cc="$ARMC6_BIN_DIR/armclang"
    (check_tools "$armc6_cc" > /dev/null 2>&1)
}

support_build_tfm_armcc () {
    support_build_armcc
}

component_build_tfm_armcc () {
    # test the TF-M configuration can build cleanly with various warning flags enabled
    cp configs/config-tfm.h "$CONFIG_H"

    msg "build: TF-M config, armclang armv7-m thumb2"
    helper_armc6_build_test "--target=arm-arm-none-eabi -march=armv7-m -mthumb -Os -std=c99 -Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wasm-operand-widths -Wunused -I../framework/tests/include/spe"
}

test_build_opt () {
    info=$1 cc=$2; shift 2
    $cc --version
    for opt in "$@"; do
          msg "build/test: $cc $opt, $info" # ~ 30s
          make CC="$cc" CFLAGS="$opt -std=c99 -pedantic -Wall -Wextra -Werror"
          # We're confident enough in compilers to not run _all_ the tests,
          # but at least run the unit tests. In particular, runs with
          # optimizations use inline assembly whereas runs with -O0
          # skip inline assembly.
          make test # ~30s
          make clean
    done
}

