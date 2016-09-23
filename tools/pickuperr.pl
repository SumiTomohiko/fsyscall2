#!/usr/local/bin/perl

# For android log, use this with $(nkf -Lu -d).

use strict;
use warnings;

while (<>) {
    if (!m/\bwrite: fd=(\d+): buf: (.*)$/) {
        next;
    }
    my ($fd, $buf) = ($1, $2);
    if (($fd != 1) && ($fd != 2)) {
        next;
    }
    $buf =~ s/\\x([0-9a-z]{2})/sub { chr(hex($_[0])) }->($1)/ge;
    print $buf;
}

# vim: shiftwidth=4 expandtab softtabstop=4
