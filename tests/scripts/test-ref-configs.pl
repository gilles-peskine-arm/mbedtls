#!/usr/bin/perl

# test-ref-configs.pl
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2013-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# For each reference configuration file in the configs directory, build the
# configuration, run the test suites and compat.sh
#
# Usage: tests/scripts/test-ref-configs.pl [config-name [...]]

use warnings;
use strict;
use File::Copy;

my %configs = (
    'config-mini-tls1_1.h' => {
        'compat' => '-m tls1_1 -f \'^DES-CBC3-SHA$\|^TLS-RSA-WITH-3DES-EDE-CBC-SHA$\'', #'
    },
    'config-suite-b.h' => {
        'compat' => "-m tls1_2 -f 'ECDHE-ECDSA.*AES.*GCM' -p mbedTLS",
    },
    'config-picocoin.h' => {
    },
    'config-ccm-psk-tls1_2.h' => {
        'compat' => '-m tls1_2 -f \'^TLS-PSK-WITH-AES-...-CCM-8\'',
    },
    'config-thread.h' => {
        'opt' => '-f ECJPAKE.*nolog',
    },
);

# If no config-name is provided, use all known configs.
# Otherwise, use the provided names only.
if ($#ARGV >= 0) {
    my %configs_ori = ( %configs );
    %configs = ();

    foreach my $conf_name (@ARGV) {
        if( ! exists $configs_ori{$conf_name} ) {
            die "Unknown configuration: $conf_name\n";
        } else {
            $configs{$conf_name} = $configs_ori{$conf_name};
        }
    }
}

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $config_h = 'include/mbedtls/config.h';
my $config_bak = "$config_h.bak";

if( -e $config_bak ) {
    die "Backup config file found: $config_bak, aborting\n";
}
rename $config_h, $config_bak or die "Failed to back up $config_h";

sub cleanup {
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

$ENV{CFLAGS} = '-Os -Werror -Wall -Wextra';

foreach my $conf (sort keys %configs) {
    my $data = $configs{$conf};
    system( "make clean" ) and die "Failed to make clean ($?)\n";

    print "\n******************************************\n";
    print "* Testing configuration: $conf\n";
    print "******************************************\n";

    copy( "configs/$conf", $config_h )
        or die "Failed to activate $conf: $!\n";

    system( "make" ) and die "Failed to build: $conf ($?)\n";
    system( "make test" ) and die "Failed test suite: $conf ($?)\n";

    my $compat = $data->{'compat'};
    if( $compat )
    {
        print "\nrunning compat.sh $compat\n";
        system( "tests/compat.sh $compat" )
            and die "Failed compat.sh: $conf ($?)\n";
    }
    else
    {
        print "\nskipping compat.sh\n";
    }

    my $opt = $data->{'opt'};
    if( $opt )
    {
        print "\nrunning ssl-opt.sh $opt\n";
        system( "tests/ssl-opt.sh $opt" )
            and die "Failed ssl-opt.sh: $conf ($?)\n";
    }
    else
    {
        print "\nskipping ssl-opt.sh\n";
    }
}

cleanup;
