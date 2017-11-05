#!/bin/sh

# Generate doxygen documentation with a full config.h (this ensures that every
# available flag is documented, and avoids warnings about documentation
# without a corresponding #define).
#
# /!\ This must not be a Makefile target, as it would create a race condition
# when multiple targets are invoked in the same parallel build.

. "$(dirname -- "$0")/lib.sh" || exit 125
save_config

scripts/config.pl realfull
make apidoc
