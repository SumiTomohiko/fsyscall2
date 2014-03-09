
from os import mkdir
from os.path import join

from fsyscall.share import drop_prefix, partial_print

def write_name_entries(p, prefix, syscalls):
    for i, syscall in enumerate(syscalls):
        name = drop_prefix(syscall.name).upper()
        sep = "," if i < len(syscalls) - 1 else ""
        p("""\
\t\"{prefix}_{name}\"{sep}\t\t\\
""".format(**locals()))

def get_key_of_call(syscall):
    return syscall.call_id

def get_key_of_ret(syscall):
    return syscall.ret_id

def write_command_name(dirpath, syscalls):
    with open(join(dirpath, "name.h"), "w") as fp:
        p, print_newline = partial_print(fp)
        p("""\
#if !defined(FSYSCALL_PRIVATE_COMMAND_NAME_H_INCLUDED)
#define\tFSYSCALL_PRIVATE_COMMAND_NAME_H_INCLUDED

#define\tCALL_NAMES\t{\t\\
""")
        write_name_entries(p, "CALL", sorted(syscalls, key=get_key_of_call))
        p("""\
}
#define\tRET_NAMES\t{\t\\
""")
        write_name_entries(p, "RET", sorted(syscalls, key=get_key_of_ret))
        p("""\
}

#endif
""")

def write_command(dirpath, syscalls):
    try:
        mkdir(dirpath)
    except OSError:
        pass
    write_command_name(dirpath, syscalls)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
