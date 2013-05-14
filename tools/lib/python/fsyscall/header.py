
from os import mkdir
from os.path import join

from fsyscall.share import drop_prefix, partial_print

def write_command_code(dirpath, syscalls):
    with open(join(dirpath, "code.h"), "w") as fp:
        p, print_newline = partial_print(fp)
        directive = "FSYSCALL_PRIVATE_COMMAND_CODE_H_INCLUDED"
        p("""\
#if !defined({directive})
#define\t{directive}
""".format(**locals()))
        print_newline()
        for i, syscall in enumerate(syscalls):
            name = drop_prefix(syscall.name).upper()
            call = i << 1
            ret = call + 1
            p("""\
#define\tCALL_{name}\t{call}
#define\tRET_{name}\t{ret}
""".format(**locals()))
        print_newline()
        p("""\
#endif
""")

def write_name_entries(p, prefix, syscalls):
    for i, syscall in enumerate(syscalls):
        name = drop_prefix(syscall.name).upper()
        sep = "," if i < len(syscalls) - 1 else ""
        p("""\
\t\"{prefix}_{name}\"{sep}\t\t\\
""".format(**locals()))

def write_command_name(dirpath, syscalls):
    with open(join(dirpath, "name.h"), "w") as fp:
        p, print_newline = partial_print(fp)
        p("""\
#if !defined(FSYSCALL_PRIVATE_COMMAND_NAME_H_INCLUDED)
#define\tFSYSCALL_PRIVATE_COMMAND_NAME_H_INCLUDED

#define\tCALL_NAMES\t{\t\\
""")
        write_name_entries(p, "CALL", syscalls)
        p("""\
}
#define\tRET_NAMES\t{\t\\
""")
        write_name_entries(p, "RET", syscalls)
        p("""\
}

#endif
""")

def write_command(dirpath, syscalls):
    try:
        mkdir(dirpath)
    except OSError:
        pass
    write_command_code(dirpath, syscalls)
    write_command_name(dirpath, syscalls)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
