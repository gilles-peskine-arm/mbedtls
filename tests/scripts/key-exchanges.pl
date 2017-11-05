#!/usr/bin/perl

# test that all configs with only a single key exchange enabled build
#
# Usage: tests/scripts/key-exchanges.pl

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $sed_cmd = 's/^#define \(MBEDTLS_KEY_EXCHANGE_.*_ENABLED\)/\1/p';
my $config_h = 'include/mbedtls/config.h';
my $config_bak = "$config_h.bak";
my $config_base = "$config_h.$$";
my @kexes = split( /\s+/, `sed -n -e '$sed_cmd' $config_h` );

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

# Prepare base config with all key exchanges disabled
system( "perl scripts/config.pl -f $config_bak -o $config_base full" )
    and die "Failed config full\n";
for my $kex (@kexes) {
    system( "scripts/config.pl -f $config_base unset $kex" )
      and die "Failed to disable $kex\n";
}

for my $kex (@kexes) {
    system( "make clean" ) and die "Failed to make clean";

    print "\n******************************************\n";
    print "* Testing with key exchange: $kex\n";
    print "******************************************\n";
    system( "scripts/config.pl -f $config_base -o $config_h set $kex" )
            and die "Failed to enable $kex\n";

    system( "make lib CFLAGS='-Os -Werror'" ) and die "Failed to build lib: $kex\n";
}

cleanup;
