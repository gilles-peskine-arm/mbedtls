# Robustness: abort on any error; abort on undefined variables
set -eu

# On normal exit or when killed by common signals, this script will:
#   * Restore config.h if it has been saved.
#   * Run "make clean" if make has been run with a modified config.h.
#   * Run the "cleanup" function.
# If you wish to perform additional cleanup steps, override the "cleanup"
# function.
cleanup () {
    :
}

# Back up the configuration file. It will be restored on exit. Refer
# to the configuration file as "$CONFIG_H". If you want to start over
# from the original version, you can read it from "$CONFIG_BAK".
save_config () {
    if [ -e "$CONFIG_BAK" ]; then
        echo >&2 "Backup config file found: $CONFIG_BAK"
        echo >&2 "This was probably left over from a broken script run."
        echo >&2 "You should check whether it needs to be restored."
        echo >&2 "$0 will not start while this file is present. Aborting."
        exit 124
    fi
    cp -p "$CONFIG_H" "$CONFIG_BAK"
    make () {
        if [ "$*" != "apidoc" ] &&
           ! cmp -s "$CONFIG_H" "$CONFIG_BAK"
        then
            ran_make_in_different_config=1
        fi
        command make "$@"
    }
}

################################################################

CONFIG_H="include/mbedtls/config.h"
CONFIG_BAK="$CONFIG_H.bak"
ran_make_in_different_config=

# Ensure that we are in an Mbed TLS toplevel directory.
if [ -e "scripts/lib.sh" ] && [ -d "programs/ssl" ]; then
    : # ok
elif [ -e "../scripts/lib.sh" ] && [ -d "../programs/ssl" ]; then
    cd ..
elif [ -e "../../scripts/lib.sh" ] && [ -d "../../programs/ssl" ]; then
    cd ../..
elif [ -e "../../../scripts/lib.sh" ] && [ -d "../../../programs/ssl" ]; then
    cd ../../..
else
    cd "$(dirname -- "$0")/.."
    if ! [ -d "programs/ssl" ]; then
        echo >&2 "Mbed TLS directory not found."
        echo >&2 "You must run this script from inside an Mbed TLS source tree."
        exit 124
    fi
fi
TOPDIR="$PWD"

# On exit, restore the config backup if there is one. Also run the function
# called "cleanup" if there is one.
exit_handler () {
    set +e
    cd "$TOPDIR"
    if [ $# -ge 1 ]; then
        trap - "$1"
    fi
    if [ -n "${CONFIG_BAK+1}" ] && [ -e "$CONFIG_BAK" ]; then
        mv "$CONFIG_BAK" "$CONFIG_H"
        if [ -n "$ran_make_in_different_config" ]; then
            # Since we restored the original config.h with its original
            # timestamp, dependency analysis might conclude that there is
            # nothing to rebuild even though there are build products from
            # a different config.h. So clean up the build products from the
            # different config.
            make clean
        fi
    fi
    cleanup
    if [ $# -ge 1 ]; then
        kill -"$1" $$
    fi
}

trap 'exit_handler' EXIT
trap 'exit_handler HUP' HUP
trap 'exit_handler INT' INT
trap 'exit_handler TERM' TERM
