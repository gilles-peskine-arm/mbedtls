#!/usr/bin/perl

# curves.pl
#
# Copyright (c) 2014-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# To test the code dependencies on individual curves in each test suite. This
# is a verification step to ensure we don't ship test suites that do not work
# for some build options.
#
# The process is:
#       for each possible curve
#           build the library and test suites with the curve disabled
#           execute the test suites
#
# And any test suite with the wrong dependencies will fail.
#
# Usage: curves.pl
#
# This script should be executed from the root of the project directory.

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $sed_cmd = 's/^#define \(MBEDTLS_ECP_DP.*_ENABLED\)/\1/p';
my $config_h = 'include/mbedtls/config.h';
my $config_bak = "$config_h.bak";
my $config_base = "$config_h.$$";
my @curves = split( /\s+/, `sed -n -e '$sed_cmd' $config_h` );

if( -e $config_bak ) {
    die "Backup config file found: $config_bak, aborting\n";
}
rename $config_h, $config_bak or die "Failed to back up $config_h";

sub cleanup {
    unlink $config_base;
    rename $config_bak, $config_h or warn "$config_h not restored\n";
    system( "make clean" );
}
sub signalled {
    cleanup;
    $SIG{$_[0]} = 'DEFAULT';
    kill $_[0], $$;
}
$SIG{HUP} = $SIG{INT} = $SIG{TERM} = \&signalled;
$SIG{__DIE__} = \&cleanup;

# depends on a specific curve. Also, ignore error if it wasn't enabled
system( "perl scripts/config.pl -f $config_bak -o $config_base unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED" );

$ENV{CFLAGS} = '-Werror -Wall -Wextra';

for my $curve (@curves) {
    system( "make clean" ) and die "Failed to make clean\n";

    print "\n******************************************\n";
    print "* Testing without curve: $curve\n";
    print "******************************************\n";

    system( "scripts/config.pl -f $config_base -o $config_h unset $curve" )
        and die "Failed to disable $curve\n";

    system( "make lib" )
        and die "Failed to build lib: $curve\n";
    system( "cd tests && make" ) and die "Failed to build tests: $curve\n";
    system( "make test" ) and die "Failed test suite: $curve\n";

}

cleanup;
