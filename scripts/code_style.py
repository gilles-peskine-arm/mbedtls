#!/usr/bin/env python3
"""Check or fix the code style by running Uncrustify.

This script must be run from the root of a Git work tree containing Mbed TLS.
"""
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
import argparse
import os
import re
import subprocess
import sys
from typing import FrozenSet, List, Optional

UNCRUSTIFY_SUPPORTED_VERSION = "0.75.1"
CONFIG_FILE = ".uncrustify.cfg"
UNCRUSTIFY_EXE = "uncrustify"
UNCRUSTIFY_ARGS = ["-c", CONFIG_FILE]
CHECK_GENERATED_FILES = "tests/scripts/check-generated-files.sh"

def print_err(*args):
    print("Error: ", *args, file=sys.stderr)

# Print the file names that will be skipped and the help message
def print_skip(files_to_skip):
    print()
    print(*files_to_skip, sep=", SKIP\n", end=", SKIP\n")
    print("Warning: The listed files will be skipped because\n"
          "they are not known to git.")
    print()

# Match FILENAME(s) in "check SCRIPT (FILENAME...)"
CHECK_CALL_RE = re.compile(r"\n\s*check\s+[^\s#$&*?;|]+([^\n#$&*?;|]+)",
                           re.ASCII)
def list_generated_files() -> FrozenSet[str]:
    """Return the names of generated files.

    We don't reformat generated files, since the result might be different
    from the output of the generator. Ideally the result of the generator
    would conform to the code style, but this would be difficult, especially
    with respect to the placement of line breaks in long logical lines.
    """
    # Parse check-generated-files.sh to get an up-to-date list of
    # generated files. Read the file rather than calling it so that
    # this script only depends on Git, Python and uncrustify, and not other
    # tools such as sh or grep which might not be available on Windows.
    # This introduces a limitation: check-generated-files.sh must have
    # the expected format and must list the files explicitly, not through
    # wildcards or command substitution.
    content = open(CHECK_GENERATED_FILES, encoding="utf-8").read()
    checks = re.findall(CHECK_CALL_RE, content)
    return frozenset(word for s in checks for word in s.split())

def get_src_files(since: Optional[str]) -> List[str]:
    """
    Use git to get a list of the source files.

    The optional argument since is a commit, indicating to only list files
    that have changed since that commit. Without this argument, list all
    files known to git.

    Only C files are included, and certain files (generated, or 3rdparty)
    are excluded.
    """
    file_patterns = ["*.[hc]",
                     "tests/suites/*.function",
                     "scripts/data_files/*.fmt"]
    output = subprocess.check_output(["git", "ls-files"] + file_patterns,
                                     universal_newlines=True)
    src_files = output.split()
    if since:
        # get all files changed in commits since the starting point
        cmd = ["git", "log", since + "..HEAD", "--name-only", "--pretty=", "--"] + src_files
        output = subprocess.check_output(cmd, universal_newlines=True)
        committed_changed_files = output.split()
        # and also get all files with uncommitted changes
        cmd = ["git", "diff", "--name-only", "--"] + src_files
        output = subprocess.check_output(cmd, universal_newlines=True)
        uncommitted_changed_files = output.split()
        src_files = list(set(committed_changed_files + uncommitted_changed_files))

    generated_files = list_generated_files()
    # Don't correct style for third-party files (and, for simplicity,
    # companion files in the same subtree), or for automatically
    # generated files (we're correcting the templates instead).
    src_files = [filename for filename in src_files
                 if not (filename.startswith("3rdparty/") or
                         filename in generated_files)]
    return src_files

def get_uncrustify_version(uncrustify_exe: str) -> str:
    """
    Get the version string from Uncrustify.

    Return an empty string if Uncrustify is not found.
    """
    try:
        output = subprocess.check_output([uncrustify_exe, "--version"],
                                         stderr=subprocess.PIPE)
        return str(output, "utf-8").strip()
    except FileNotFoundError:
        sys.stderr.write('Fatal: command {} not found in PATH.\n'
                         .format(uncrustify_exe))
        return ''

def check_style_is_correct(uncrustify_exe: str,
                           src_file_list: List[str]) -> bool:
    """
    Check the code style and output a diff for each file whose style is
    incorrect.
    """
    style_correct = True
    for src_file in src_file_list:
        uncrustify_cmd = [uncrustify_exe] + UNCRUSTIFY_ARGS + [src_file]
        result = subprocess.run(uncrustify_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
        if result.returncode != 0:
            print_err("Uncrustify returned " + str(result.returncode) +
                      " correcting file " + src_file)
            return False

        # Uncrustify makes changes to the code and places the result in a new
        # file with the extension ".uncrustify". To get the changes (if any)
        # simply diff the 2 files.
        diff_cmd = ["diff", "-u", src_file, src_file + ".uncrustify"]
        cp = subprocess.run(diff_cmd, check=False)

        if cp.returncode == 1:
            print(src_file + " changed - code style is incorrect.")
            style_correct = False
        elif cp.returncode != 0:
            raise subprocess.CalledProcessError(cp.returncode, cp.args,
                                                cp.stdout, cp.stderr)

        # Tidy up artifact
        os.remove(src_file + ".uncrustify")

    return style_correct

def fix_style_single_pass(src_file_list: List[str]) -> bool:
    """
    Run Uncrustify once over the source files.
    """
    code_change_args = UNCRUSTIFY_ARGS + ["--no-backup"]
    for src_file in src_file_list:
        uncrustify_cmd = [UNCRUSTIFY_EXE] + code_change_args + [src_file]
        result = subprocess.run(uncrustify_cmd, check=False)
        if result.returncode != 0:
            print_err("Uncrustify with file returned: " +
                      str(result.returncode) + " correcting file " +
                      src_file)
            return False
    return True

def fix_style(uncrustify_exe: str, src_file_list: List[str]) -> int:
    """
    Fix the code style. This takes 2 passes of Uncrustify.
    """
    if not fix_style_single_pass(src_file_list):
        return 1
    if not fix_style_single_pass(src_file_list):
        return 1

    # Guard against future changes that cause the codebase to require
    # more passes.
    if not check_style_is_correct(uncrustify_exe, src_file_list):
        print_err("Code style still incorrect after second run of Uncrustify.")
        return 1
    else:
        return 0

def main() -> int:
    """
    Main with command line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fix', action='store_true',
                        help=('modify source files to fix the code style '
                              '(default: print diff, do not modify files)'))
    parser.add_argument('-s', '--since', metavar='COMMIT', const='development', nargs='?',
                        help=('only check files modified since the specified commit'
                              ' (e.g. --since=HEAD~3 or --since=development). If no'
                              ' commit is specified, default to development.'))
    # --subset is almost useless: it only matters if there are no files
    # ('code_style.py' without arguments checks all files known to Git,
    # 'code_style.py --subset' does nothing). In particular,
    # 'code_style.py --fix --subset ...' is intended as a stable ("porcelain")
    # way to restyle a possibly empty set of files.
    parser.add_argument('--subset', action='store_true',
                        help='only check the specified files (default with non-option arguments)')
    parser.add_argument('--uncrustify',
                        default='uncrustify',
                        help='uncrustify command to run (default: uncrustify)')
    parser.add_argument('operands', nargs='*', metavar='FILE',
                        help='files to check (files MUST be known to git, if none: check all)')

    args = parser.parse_args()

    uncrustify_version = get_uncrustify_version(args.uncrustify)
    if UNCRUSTIFY_SUPPORTED_VERSION not in uncrustify_version:
        if uncrustify_version != '':
            sys.stderr.write('Fatal: wrong uncrustify version ({}).\n'
                             .format(uncrustify_version))
        sys.stderr.write('You need uncrustify {} for correct results.\n'
                         .format(UNCRUSTIFY_SUPPORTED_VERSION))
        return 2

    covered = frozenset(get_src_files(args.since))
    # We only check files that are known to git
    if args.subset or args.operands:
        src_files = [f for f in args.operands if f in covered]
        skip_src_files = [f for f in args.operands if f not in covered]
        if skip_src_files:
            print_skip(skip_src_files)
    else:
        src_files = list(covered)

    if args.fix:
        # Fix mode
        return fix_style(args.uncrustify, src_files)
    else:
        # Check mode
        if check_style_is_correct(args.uncrustify, src_files):
            print("Checked {} files, style ok.".format(len(src_files)))
            return 0
        else:
            return 1

if __name__ == '__main__':
    sys.exit(main())
