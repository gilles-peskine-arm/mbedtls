#!/bin/sh

. "$(dirname -- "$0")/../../scripts/lib.sh" || exit 125
save_config

if grep -i cmake Makefile >/dev/null; then
    echo "$0: not compatible with cmake" >&2
    exit 1
fi

case $(uname) in
  *Darwin*)
    run_nm () {
      nm -gUj library/libmbed*.a 2>/dev/null |
        sed -n -e 's/^_//p'
    };;
  *Linux*)
    run_nm () {
      nm -og library/libmbed*.a |
        grep -v '^[^ ]*: *U \|^$\|^[^ ]*:$' |
        sed 's/^[^ ]* . //'
    };;
  *) echo "$0: operating system not supported" >&2; exit 1;;
esac

scripts/config.pl full

CFLAGS=-fno-asynchronous-unwind-tables make clean lib >/dev/null 2>&1
run_nm | sort > exported-symbols
wc -l exported-symbols
