#!/usr/bin/env perl

# test-ref-configs.pl
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use warnings;
use strict;
use Getopt::Std;
use POSIX qw(SIGINT);

my %configs = (
    'config-ccm-psk-tls1_2.h' => {
        'compat' => '-m tls12 -f \'^TLS-PSK-WITH-AES-...-CCM-8\'',
        'test_again_with_use_psa' => 1
    },
    'config-ccm-psk-dtls1_2.h' => {
        'compat' => '-m dtls12 -f \'^TLS-PSK-WITH-AES-...-CCM-8\'',
        'opt' => ' ',
        'opt_needs_debug' => 1,
        'test_again_with_use_psa' => 1
    },
    'config-no-entropy.h' => {
    },
    'config-suite-b.h' => {
        'compat' => "-m tls12 -f 'ECDHE-ECDSA.*AES.*GCM' -p mbedTLS",
        'test_again_with_use_psa' => 1,
        'opt' => ' ',
        'opt_needs_debug' => 1,
    },
    'config-symmetric-only.h' => {
        'test_again_with_use_psa' => 0, # Uses PSA by default, no need to test it twice
    },
    'config-thread.h' => {
        'opt' => '-f ECJPAKE.*nolog',
        'test_again_with_use_psa' => 1,
    },
);

sub HELP_MESSAGE {
    my ($fh) = @_;
    print $fh <<EOF;
Usage: $0 [OPTION]... [CONFIG_NAME [...]]

For each reference configuration file in the configs directory, build the
configuration, run the test suites and, for some configurations, TLS tests.
If given one or more config name, only test these configurations.

Options:
  -k            Keep going after errors
  --help        Print this help and exit

Config names:
EOF
    print $fh map {"  $_\n"} sort keys %configs;
}
sub VERSION_MESSAGE {
}

my %opts;
$Getopt::Std::STANDARD_HELP_VERSION = 1;
getopts('k', \%opts);

# If no config-name is provided, use all known configs.
# Otherwise, use the provided names only.
my @configs_to_test = sort keys %configs;
if ($#ARGV >= 0) {
    foreach my $conf_name ( @ARGV ) {
        if( ! exists $configs{$conf_name} ) {
            die "Unknown configuration: $conf_name\n";
        }
    }
    @configs_to_test = @ARGV;
}

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $config_h = 'include/mbedtls/mbedtls_config.h';

system( "cp $config_h $config_h.bak" ) and die;

my $failures = 0;

sub abort {
    warn $_[0];
    my $sig = $? & 127;
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    if ( $sig == POSIX::SIGINT )
    {
        warn "\nInterrupted during build\n";
        $SIG{'INT'} = 'DEFAULT';
        kill( $sig, $$ );
    }
    elsif ( $opts{k} )
    {
        die "failure";
    }
    else
    {
        # use an exit code between 1 and 124 for git bisect (die returns 255)
        exit 1;
    }
}

sub interrupt {
    warn "\nInterrupted during perl\n";
    die "interrupt";
}
$SIG{INT} = \&interrupt;

# Create a seedfile for configurations that enable MBEDTLS_ENTROPY_NV_SEED.
# For test purposes, this doesn't have to be cryptographically random.
if (!-e "tests/seedfile" || -s "tests/seedfile" < 64) {
    local *SEEDFILE;
    open SEEDFILE, ">tests/seedfile" or die;
    print SEEDFILE "*" x 64 or die;
    close SEEDFILE or die;
}

sub perform_test {
    my $conf = $_[0];
    my $conf_file = "configs/$conf";
    my $data = $_[1];
    my $test_with_psa = $_[2];

    if ( $test_with_psa )
    {
        $conf .= '+USE_PSA_CRYPTO';
    }

    system( "cp $config_h.bak $config_h" ) and die "fatal";
    system( "make clean" ) and die "fatal";

    print "\n******************************************\n";
    print "* Testing configuration: $conf\n";
    print "******************************************\n";

    $ENV{MBEDTLS_TEST_CONFIGURATION} = $conf;

    system( "cp $conf_file $config_h" )
        and abort "Failed to activate $conf\n";

    if ( $test_with_psa )
    {
        system( "scripts/config.py set MBEDTLS_PSA_CRYPTO_C" );
        system( "scripts/config.py set MBEDTLS_USE_PSA_CRYPTO" );
    }

    system( "CFLAGS='-Os -Werror -Wall -Wextra' make" ) and abort "Failed to build: $conf\n";
    system( "make test" ) and abort "Failed test suite: $conf\n";

    my $compat = $data->{'compat'};
    if( $compat )
    {
        print "\nrunning compat.sh $compat\n";
        system( "tests/compat.sh $compat" )
            and abort "Failed compat.sh: $conf\n";
    }
    else
    {
        print "\nskipping compat.sh\n";
    }

    my $opt = $data->{'opt'};
    if( $opt )
    {
        if( $data->{'opt_needs_debug'} )
        {
            print "\nrebuilding with debug traces for ssl-opt\n";
            system( "make clean" );
            system( "scripts/config.py set MBEDTLS_DEBUG_C" );
            system( "scripts/config.py set MBEDTLS_ERROR_C" );
            system( "CFLAGS='-Os -Werror -Wall -Wextra' make" ) and abort "Failed to build: $conf+DEBUG\n";
        }

        print "\nrunning ssl-opt.sh $opt\n";
        system( "tests/ssl-opt.sh $opt" )
            and abort "Failed ssl-opt.sh: $conf\n";
    }
    else
    {
        print "\nskipping ssl-opt.sh\n";
    }
}

sub wrap_test {
    eval {
        perform_test( @_ )
    };
    warn "\$\@ = \"$@\"\n";
    if ( $@ eq "failure" ) {
        ++$failures;
    } else {
        die $@;
    }
}

foreach my $conf ( @configs_to_test ) {
    my $test_with_psa = $configs{$conf}{'test_again_with_use_psa'};
    if ( $test_with_psa )
    {
        wrap_test( $conf, $configs{$conf}, $test_with_psa );
    }
    wrap_test( $conf, $configs{$conf}, 0 );
}

system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
system( "make clean" );
exit !$failures;
