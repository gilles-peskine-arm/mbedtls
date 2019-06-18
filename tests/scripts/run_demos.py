#!/usr/bin/env python3
"""Run the Mbed TLS demo scripts.
"""
import glob
import re
import subprocess

def config_has(symbol):
    return subprocess.call(['scripts/config.pl', symbol]) == 0

def is_demo_applicable(demo):
    """Return True if the specified demo is applicable in the current configuration."""
    # For the time being, just do an ad hoc detection of demos that need PSA.
    # This should be made more principled when we add more demos.
    if re.search(r'[/_]psa[/_]', demo):
        return config_has('MBEDTLS_PSA_CRYPTO_C')
    return True

def run_demo(demo):
    """Run the specified demo script. Return True if it succeeds."""
    returncode = subprocess.call([demo])
    return returncode == 0

def run_demos(demos):
    """Run the specified demos and print summary information about failures.

Return True if all demos passed and False if a demo fails."""
    failures = []
    for demo in demos:
        print('#### {} ####'.format(demo))
        if not run_demo(demo):
            failures.append(demo)
            print('{}: FAIL'.format(demo))
        print('')
    successes = len(demos) - len(failures)
    print('{}/{} demos passed'.format(successes, len(demos)))
    if failures:
        print('Failures:', *failures)
    return not failures

def run_all_demos():
    """Run all the available demos that are application in the current configuration.

Return True if all demos passed and False if a demo fails."""
    all_demos = (glob.glob('programs/*/*_demo.sh') +
                 glob.glob('crypto/programs/*/*_demo.sh'))
    applicable_demos = [demo for demo in all_demos if is_demo_applicable(demo)]
    return run_demos(applicable_demos)

if __name__ == '__main__':
    if not run_all_demos():
        exit(1)
