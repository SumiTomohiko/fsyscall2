#!/usr/local/bin/python3

from os import getcwd
from os.path import abspath, dirname, join
from sys import argv, exit, path

path.insert(0, join(dirname(abspath(__file__)), "lib", "python"))

from fsyscall import java, master, mhub, shub, slave
from fsyscall.code import read_codes, write_names
from fsyscall.syscalls import read_syscalls

def find_syscall_of_name(syscalls, name):
    a = [syscall for syscall in syscalls if syscall.const_name == name]
    try:
        return a[0]
    except IndexError:
        fmt = """\
In numbering the syscalls, {name} not found in syscalls.master. You must remove
it from include/fsyscall/private/command/code.h manually.
"""
        print(fmt.format(**locals()))
        exit(1)

def number_syscalls(syscalls, codes):
    for code in codes:
        name = code.name
        if (not name.startswith("CALL_")) and (not name.startswith("RET_")):
            continue
        which, name = name.split("_", 1)
        syscall = find_syscall_of_name(syscalls, name)
        attr = "call_id" if which == "CALL" else "ret_id"
        setattr(syscall, attr, code.value)

def find_unnumbered_syscall(syscalls, header):
    for syscall in syscalls:
        fmt = """\
syscall {name} is not assigned with any numbers for {which}.
Did you add an entry into {header}?
"""
        name = syscall.name
        if syscall.call_id is None:
            which = "call"
            print(fmt.format(**locals()))
            exit(1)
        if syscall.ret_id is None:
            which = "ret"
            print(fmt.format(**locals()))
            exit(1)

def main(dirpath):
    fmaster_root = join(dirpath, "fmaster")
    fmaster_dir = join(fmaster_root, "sys", "fmaster")
    private_dir = join(dirpath, "include", "fsyscall", "private")
    header = join(private_dir, "command", "code.h")

    codes = read_codes(header)
    syscalls = read_syscalls(fmaster_dir)
    number_syscalls(syscalls, codes)
    find_unnumbered_syscall(syscalls, header)

    MAKEFILE = "Makefile.makesyscalls"

    master.write_implementation(fmaster_dir, syscalls)
    master.write_pre_post_h(fmaster_dir, syscalls)
    master.write_fmaster_makefile(join(fmaster_root, MAKEFILE), syscalls)

    write_names(join(dirpath, "lib", "command", "names.inc"), codes)

    fslave_dir = join(dirpath, "fslave")
    slave.write_fslave(fslave_dir, syscalls)
    slave.write_dispatch(fslave_dir, syscalls)
    slave.write_fslave_makefile(join(fslave_dir, MAKEFILE), syscalls)
    slave.write_proto(join(private_dir, "fslave"), syscalls)

    shub.write_fshub_dispatch(join(dirpath, "fshub"), syscalls)
    mhub.write_fmhub_dispatch(join(dirpath, "fmhub"), syscalls)

    java.write(join(dirpath, "java"), syscalls)

if __name__ == "__main__":
    main(abspath(getcwd()) if len(argv) != 2 else argv[1])

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
