#!/usr/bin/env python3
"""Run the Mbed TLS demo scripts.
"""
import glob
import re
import subprocess
import sys

# Read the library configuration.
import scripts.config
CONFIG = scripts.config.ConfigFile()

def read_dependencies(demo):
    """Read and parse a depends_on line from a demo script.

    The format of a depends_on line is similar to test suites:
    a line containing the string 'depends_on:' followed by zero or more
    colon-separated preprocessor symbols (no whitespace permitted). The
    'depends_on:' string must be at the beginning of a line, preceded only
    by optional whitespace and an optional comment start ('#' characters).
    Negative dependencies are not supported.
    Only the first 'depends_on:' line is read.
    """
    with open(demo, 'rb') as stream:
        for line in stream:
            m = re.match(rb'[\s#]*depends_on:([\w:]*)', line)
            if m:
                dependencies = m.group(1).split(b':')
                return [dep.decode('ascii') for dep in dependencies if dep]
    # If there is no depends_on line, assume there are no dependencies.
    return []

def is_demo_applicable(demo):
    """Whether the specified demo is applicable in the current configuration."""
    dependencies = read_dependencies(demo)
    return CONFIG.all(*dependencies)

def run_demo(demo):
    """Run the specified demo script. Return True if it succeeds."""
    returncode = subprocess.call([demo])
    return returncode == 0

def run_demos(demos):
    """Run the specified demos and print summary information about failures.

Return True if all demos passed and False if a demo fails."""
    failures = []
    skipped_count = 0
    success_count = 0
    for demo in demos:
        print('#### {} ####'.format(demo))
        if not is_demo_applicable(demo):
            skipped_count += 1
            print('SKIP (unmet dependencies)')
            continue
        if run_demo(demo):
            success_count += 1
        else:
            failures.append(demo)
            print('{}: FAIL'.format(demo))
        print('')
    print('{}/{} demos passed, {} skipped'
          .format(success_count, len(demos) - len(failures), skipped_count))
    if failures:
        print('Failures:', *failures)
    return not failures

def run_all_demos():
    """Run all the available demos that are application in the current configuration.

Return True if all demos passed and False if a demo fails."""
    all_demos = glob.glob('programs/*/*_demo.sh')
    return run_demos(all_demos)

if __name__ == '__main__':
    if not run_all_demos():
        sys.exit(1)
