#!/usr/bin/env perl
# Test script for the OS function offloading mechanism
# Typical usage:
#   P_SRV_WRAPPER=./wrap-serializer.pl P_CLI_WRAPPER=./wrap-serializer.pl ./tests/ssl-opt.sh

# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2017, ARM Limited, All Rights Reserved
#  SPDX-License-Identifier: Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# This script runs a program using libmbedssl ("target program") which is
# assumed to have been compiled with operating system functionality
# offloaded (MBEDTLS_NET_OFFLOAD_C). This script also runs an instance
# of the host frontend to perform the offloaded functionality. The offloaded
# functionality runs on the same machine: this script is only intended for
# testing. All the command line arguments for this script are passed to the
# target program.

# This script is intended to be run in an mbedtls source tree. The host
# frontend must be present at ../programs/host/frontend relative to the
# location of this script.

use warnings;
use strict;
use POSIX;
use FindBin qw($Bin);

#### Set up signal handling ####

my ($host_pid, $target_pid);
my ($host_status, $target_status);
my $killed_host;
sub relay_signal {
    my ($sig) = @_;
    printf STDERR "Relaying signal %s\n", $sig;
    if ($host_pid && !defined $host_status) {
        $killed_host = $sig;
        kill($sig, $host_pid);
    }
    if ($target_pid && !defined $target_status) {
        kill($sig, $target_pid);
    }
}
$SIG{'INT'} = \&relay_signal;
$SIG{'TERM'} = \&relay_signal;

#### Set up communication pipes between the host and the target.

{
    my $null_fd = POSIX::open('/dev/null') or die "open /dev/null: $!";
    dup2($null_fd, 3) or die "dup2: $!";
    dup2($null_fd, 4) or die "dup2: $!";
    close($null_fd) unless $null_fd == 3 || $null_fd == 4;
}
my ($target_to_host_read, $host_to_target_write, $host_to_target_read, $target_to_host_write);
pipe($target_to_host_read, $target_to_host_write) or die "pipe: $!";
pipe($host_to_target_read, $host_to_target_write) or die "pipe: $!";

#### Fork the host frontend ####

$host_pid = fork();
if (!defined $host_pid) {
    die "fork: $!";
} elsif (!$host_pid) {
    dup2(fileno($target_to_host_read), 3) or die "dup2: $!";
    dup2(fileno($host_to_target_write), 4) or die "dup2: $!";
    close($host_to_target_read);
    close($target_to_host_write);
    close($target_to_host_read);
    close($host_to_target_write);
    my $frontend = $FindBin::Bin . '/../programs/host/frontend';
    my @prefix;
    #@prefix = qw(strace -o frontend.strace -etrace=read,write -eread=3 -ewrite=4);
    exec @prefix, $frontend or die "exec $frontend: $!";
}
close($target_to_host_read);
close($host_to_target_write);
POSIX::close(3);
POSIX::close(4);

#### Fork the target program ####

$target_pid = fork();
if (!defined $target_pid) {
    die "fork: $!";
} elsif (!$target_pid) {
    dup2(fileno($target_to_host_write), 3) or die "dup2: $!";
    dup2(fileno($host_to_target_read), 4) or die "dup2: $!";
    close($host_to_target_read);
    close($target_to_host_write);
    my @prefix;
    #@prefix = qw(strace -o target.strace -etrace=read,write -eread=4 -ewrite=3);
    exec @prefix, @ARGV or do {
        my $exec_error = $!;
        kill 'HUP', $host_pid;
        die "exec $ARGV[0]: $exec_error";
    };
}

#### Wait for both programs to exit ####

foreach (qw(host target)) {
    my $dead = wait();
    if ($dead == $target_pid) {
        $target_status = $?;
        printf STDERR "Reaped target, status=0x%04x\n", $target_status;
    } elsif ($dead == $host_pid) {
        $host_status = $?;
        printf STDERR "Reaped host, status=0x%04x\n", $host_status;
    } else {
        die "Unknown child $dead";
    }
    if (defined($host_status) && !defined $target_status && !$killed_host) {
        if ($host_status & 0xff) {
            warn "Frontend killed by signal ", $host_status & 0xff;
        } else {
            warn "Frontend exited with status ", $host_status >> 8;
        }
        kill 'HUP', $target_pid;
    } elsif (defined $target_status && !defined $host_status) {
        ## Send the frontend an exit instruction. Read but ignore the
        ## response.
        syswrite($target_to_host_write, "\x45\x00\x01\x00");
        my $ignored;
        sysread($host_to_target_read, $ignored, 4);
    }
}

my $status = ($host_status ? $host_status : $target_status);
$status = $status & 0xff ? $status | 0x80 : $status >> 8;
exit($status);
