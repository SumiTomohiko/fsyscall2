#!/usr/local/bin/perl

# For android log, use this with $(nkf -Lu -d).

while (<>) {
    if (m/\bwrite\(2\) (for|to) fd 2: buf\[\d+\]=(0x[0-9a-f]{2}) \(.\)$/) {
        print chr(hex($2));
        next;
    }
}

# vim: shiftwidth=4 expandtab softtabstop=4
