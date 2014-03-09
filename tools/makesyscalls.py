#!/usr/local/bin/python3

from os import getcwd
from os.path import abspath, dirname, join
from sys import argv, path

path.insert(0, join(dirname(abspath(__file__)), "lib", "python"))

from fsyscall import java, master, mhub, shub, slave
from fsyscall.syscalls import read_syscalls

def main(dirpath):
    fmaster_root = join(dirpath, "fmaster")
    fmaster_dir = join(fmaster_root, "sys", "fmaster")
    syscalls = read_syscalls(fmaster_dir)

    MAKEFILE = "Makefile.makesyscalls"

    master.write_implementation(fmaster_dir, syscalls)
    master.write_pre_post_h(fmaster_dir, syscalls)
    master.write_fmaster_makefile(join(fmaster_root, MAKEFILE), syscalls)

    fslave_dir = join(dirpath, "fslave")
    slave.write_fslave(fslave_dir, syscalls)
    slave.write_dispatch(fslave_dir, syscalls)
    slave.write_fslave_makefile(join(fslave_dir, MAKEFILE), syscalls)
    slave_proto_dir = join(dirpath, "include", "fsyscall", "private", "fslave")
    slave.write_proto(slave_proto_dir, syscalls)

    shub.write_fshub_dispatch(join(dirpath, "fshub"), syscalls)
    mhub.write_fmhub_dispatch(join(dirpath, "fmhub"), syscalls)

    java.write(join(dirpath, "java"), syscalls)

if __name__ == "__main__":
    main(abspath(getcwd()) if len(argv) != 2 else argv[1])

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
