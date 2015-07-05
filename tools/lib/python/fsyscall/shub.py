
from os.path import join

from fsyscall.share import SYSCALLS, make_cmd_name, partial_print,  \
                           write_c_footer

def write_cases(path, syscalls, suffix):
    with open(path, "w") as fp:
        p, _ = partial_print(fp)
        for syscall in syscalls:
            if syscall.name not in SYSCALLS:
                continue
            cmd = make_cmd_name(syscall.name)
            p("""\
\tcase {cmd}_{suffix}:
""".format(**locals()))
        write_c_footer(p)

def write_fshub_dispatch(dirpath, syscalls):
    write_cases(join(dirpath, "dispatch_call.inc"), syscalls, "CALL")
    write_cases(join(dirpath, "dispatch_ret.inc"), syscalls, "RETURN")

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
