#!/usr/local/bin/perl

while (<>) {
    if (m/ kernel: fmaster\[\d+\]: write\(2\) to fd 2: buf\[\d+\]=(0x[0-9a-f]{2}) \(.\)$/) {
        print chr(hex($1));
    }
}

# vim: shiftwidth=4 expandtab softtabstop=4
