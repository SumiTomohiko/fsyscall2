#!/usr/local/bin/perl

# usage: unexpected_ENOENT [-a]
#   -a: show all ENOENT

use strict;
use warnings;

my @knowns = qw[
    /hicolor$
    /icon-theme.cache$
    ^/.config/fontconfig/conf.d$
    ^/.config/fontconfig/fonts$
    ^/.config/fontconfig/fonts.conf$
    ^/.local/share/fonts$
    ^/bin/
    ^/etc/nvidia/nvidia-application-profiles-rc$
    ^/etc/nvidia/nvidia-application-profiles-rc.d/
    ^/etc/xdg/gtk-3.0/settings.ini$
    ^/home/\w+/
    ^/proc/\d+/cmdline$
    ^/tmp/dbus-\w+$
    ^/usr/bin/
    ^/usr/local/bin/
    ^/usr/local/etc/dbus-1/session-local$
    ^/usr/local/etc/dconf/profile/user$
    ^/usr/local/etc/fonts/local.conf$
    ^/usr/local/etc/gtk-2.0/gtkrc$
    ^/usr/local/etc/gtk-3.0/settings.ini$
    ^/usr/local/etc/libmap.d$
    ^/usr/local/etc/xdg/gtk-2.0/gtkrc$
    ^/usr/local/etc/xdg/gtk-3.0/settings.ini$
    ^/usr/local/lib/X11/fonts$
    ^/usr/local/lib/gedit/plugins/\w+(?!.so)$
    ^/usr/local/share/create/swatches$
    ^/usr/local/share/dconf/profile/user$
    ^/usr/local/share/gtk-2.0/gtkrc$
    ^/usr/local/share/gtk-3.0/settings.ini$
    ^/usr/local/share/mime/
    ^/usr/local/share/nls/C/libc.cat$
    ^/usr/local/share/nls/libc/C$
    ^/usr/local/share/themes/Adwaita/gtk-3.0/settings.ini$
    ^/usr/share/dbus-1/services$
    ^/usr/share/locale/locale.alias$
    ^/usr/share/nls/C/libc.cat$
    ^/usr/share/nls/libc/C$
    ^/usr/share/nvidia/nvidia-application-profiles-346.96-rc$
    ^/usr/share/nvidia/nvidia-application-profiles-rc$
    ^/var/run/console/\w+$
    lib[-\.\w\+]+.so.\d+
    nss_(compat|dns|files|nis).so.1];

while ((0 < @ARGV) && ($ARGV[0] =~ m/^(-.)/)) {
    my ($opt) = ($1);

    if ($opt eq "-a") {
        @knowns = ();
    }

    shift @ARGV;
}

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
    s%/+%/%g;
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
