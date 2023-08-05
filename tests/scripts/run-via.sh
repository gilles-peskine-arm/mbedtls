#!/bin/sh

# Automagically tweak the way we run an mbedtls program to handle certain
# test conditions.

set -eu

hack_LD_PRELOAD () {
    if ! type ldd >/dev/null 2>/dev/null; then
        # We aren't on Linux. Don't try anything.
        return
    fi
    # Sanitizers (Asan, UBsan, Msan) want to be loaded first (at least
    # with GCC 11). This is incompatible with normal use of LD_PRELOAD,
    # for example when running under faketime. So if the test are linked
    # with a sanitizer which is dynamically linked before libc, preload it
    # explicitly before whatever is already in $LD_PRELOAD.
    LD_PRELOAD=$(
        ldd "$1" |
        sed -n '/^\tlibc\./q;
                s!^.* \(/.*/lib[a-z][a-z]*\.so\.[^ ]*\) .*$!\1!p' |
        tr \\n :)$LD_PRELOAD
}

if [ -n "${LD_PRELOAD:-}" ]; then
    hack_LD_PRELOAD "$@"
fi

exec "$@"
