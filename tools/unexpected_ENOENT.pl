#!/usr/local/bin/perl

use strict;
use warnings;

my @knowns = [];

sub key {
    my ($pid, $tid) = @_;
    return $pid . $tid;
}

my %pathes = ();

while (<>) {
    if (m/\bfmaster\[(\d+)\]: (?:tid=(0x[0-9a-f]+): )?open: started: path=\"(.*)\"/) {
        my ($pid, $tid, $path) = ($1, defined($2) ? $2 : "", $3);
        $pathes{key($pid, $tid)} = $path;
        next;
    }
    if (m/\bfmaster\[(\d+)\]: (?:tid=(0x[0-9a-f]+): )?open: ended: .*, error=2 \(ENOENT\)/) {
        my ($pid, $tid) = ($1, defined($2) ? $2 : "");
        my $key = key($pid, $tid);
        my $path = $pathes{$key};
        delete $pathes{$key};
        if (!grep { $_ eq $path } @knowns) {
            printf "pid=%s, tid=%s, path=%s\n", $pid, $tid, $path;
        }
        next;
    }
}

# vim: shiftwidth=4 expandtab softtabstop=4
