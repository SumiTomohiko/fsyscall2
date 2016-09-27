#!/usr/local/bin/perl

# For android log, use this with $(nkf -Lu -d).

use strict;
use warnings;

sub decode {
    my ($code) = @_;

    if ($code eq "\\\\") {
        return "\\";
    }
    elsif ($code eq "\\n") {
        return "\n";
    }
    elsif ($code eq "\\t") {
        return "\t";
    }
    elsif ($code eq "\\0") {
        return "";
    }
    elsif ($code =~ m/\\x([0-9a-f]{2})/) {
        return chr(hex($1));
    }
}

while (<>) {
    if (!m/\bwrite: fd=(\d+): buf: (.*)$/) {
        next;
    }
    my ($fd, $buf) = ($1, $2);
    if (($fd != 1) && ($fd != 2)) {
        next;
    }
    $buf =~ s/(\\(?:x[0-9a-f]{2}|[\\nt0]))/decode($1)/ge;
    print $buf;
}

# vim: shiftwidth=4 expandtab softtabstop=4
