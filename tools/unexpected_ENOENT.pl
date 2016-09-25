#!/usr/local/bin/perl

use strict;
use warnings;

my @knowns = [];

sub defined_or_empty {
    my ($s) = @_;
    return defined($s) ? $s : "";
}

sub key {
    my ($pid, $tid) = @_;
    return $pid . defined_or_empty($tid);
}

my %pathes = ();

while (<>) {
    if (m/\bfmaster\[(\d+)\]: (?:tid=(0x[0-9a-f]+): )?(?:access|open|stat|lstat): started: path=\"(.*)\"/) {
        my ($pid, $tid, $path) = ($1, $2, $3);
        $pathes{key($pid, $tid)} = $path;
        next;
    }
    if (m/\bfmaster\[(\d+)\]: (?:tid=(0x[0-9a-f]+): )?openat: started: fd=-?\d+, path=\"(.*)\"/) {
        my ($pid, $tid, $path) = ($1, $2, $3,);
        $pathes{key($pid, $tid)} = $path;
        next;
    }
    if (m/\bfmaster\[(\d+)\]: (?:tid=(0x[0-9a-f]+): )?(access|open|openat|stat|lstat): ended: .*, error=2 \(ENOENT\)/) {
        my ($pid, $tid, $sysname) = ($1, $2, $3);
        my $key = key($pid, $tid);
        my $path = $pathes{$key};
        delete $pathes{$key};

        $path = defined($path) ? $path : "unkown";
        if (!grep { $path =~ m/$_/ } @knowns) {
            my $fmt = "pid=%s, tid=%s, sysname=%s, path=%s\n";
            printf $fmt, $pid, defined_or_empty($tid), $sysname, $path;
        }
        next;
    }
}

# vim: shiftwidth=4 expandtab softtabstop=4
