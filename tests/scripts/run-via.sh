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
        ldd -- "$1" |
        sed -n '/^\tlibc\./q;
                s!^.* \(/.*/lib[a-z][a-z]*\.so\.[^ ]*\) .*$!\1!p' |
        tr \\n :)$LD_PRELOAD

    # If we're running a 32-bit program on a 64-bit host, try substituting
    # a 32-bit library for a 64-bit library. If in doubt, leave the library
    # unchanged, which will likely result the library being ignored with
    # a warning when running the program.
    if [ "$(uname -m)" = "x86_64" ] &&
        case $(ldd -- "$1") in
            */lib/i?86-*|*/lib32/*) true;;
            *) false;;
        esac
    then
        IFS=:; set +f
        new_list=
        for lib in $LD_PRELOAD; do
            case $lib in
                */lib/*)
                    lib32=${lib%%/lib/*}/lib32/${lib#*/lib/}
                    if [ -e "$lib32" ]; then
                        lib=$lib32
                    fi
                    unset lib32
            esac
            new_list=$new_list:$lib
        done
        LD_PRELOAD=${new_list#:}
        unset IFS; set -f
        unset lib new_list
    fi
}

if [ -n "${LD_PRELOAD:-}" ]; then
    hack_LD_PRELOAD "$@"
fi

exec "$@"
