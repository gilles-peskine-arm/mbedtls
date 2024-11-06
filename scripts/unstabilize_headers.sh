#!/bin/sh

# Temporary maintainer script.
# Change #include statements that reference an unstable header to use its
# new location in the mbedtls/unstable subdirectory.
# Also change #include statements in unstable headers that reference stable
# headers to point to the stable directory.
# Assume we don't use the same base name for a stable header and an
# unstable header.
# This script is idempotent, so it can be run more than once to handle
# successive header moves.
# This script does not account for headers being moved out of the unstable
# subdirectory.

set -eu

# Rewrite include statements in C source files managed by Git.
# Assumes $UNSTABLE_HEADERS contains the list of header base names that have
# moved to the unstable subdirectory.
# Assumes no funky characters in file names.
rewrite_include_statements_to_unstable () {
    git ls-files '**/*.h' '**/*.c' '**/*.function' scripts/data_files/query_config.fmt |
    xargs perl -i -pe '
        BEGIN {
            local $_ = $ENV{UNSTABLE_HEADERS};
            s/\s+/\|/g;
            s/\./\\./g;
            our $header_re = "(?:$_)";
        }
        s!(#\s*include\s*[<"]mbedtls)/(${header_re}[>"])!$1/unstable/$2!
    '
}

# Switch to the root directory
case $PWD in
    */tf-psa-crypto/*) cd -- "${PWD%tf-psa-crypto/*}";;
    */tf-psa-crypto) cd ..;;
esac

# Space-separated of header base names
export STABLE_HEADERS="$(cd tf-psa-crypto/drivers/builtin/include/mbedtls && echo *.h)"
export UNSTABLE_HEADERS="$(cd tf-psa-crypto/drivers/builtin/include/mbedtls/unstable && echo *.h)"

# Rewrite C source files that include unstable headers.
rewrite_include_statements_to_unstable
cd framework
rewrite_include_statements_to_unstable
cd ..

# Rewrite unstable headers that include a stable header.
perl -i -pe '
        BEGIN {
            local $_ = $ENV{STABLE_HEADERS};
            s/\s+/\|/g;
            s/\./\\./g;
            our $header_re = "(?:$_)";
        }
        s!(#\s*include\s*[<"])(${header_re}[>"])!$1../$2!
' tf-psa-crypto/drivers/builtin/include/mbedtls/unstable/*.h
