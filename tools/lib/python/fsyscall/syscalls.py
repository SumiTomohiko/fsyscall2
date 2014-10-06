
from os.path import exists, join
from re import search, split, sub
from sys import exit

from fsyscall.share import Variable, data_of_argument, drop_prefix

class Syscall:

    def __init__(self):
        self.rettype = None
        self.name = None
        self.args = []
        self.sending_order_args = None
        self.pre_execute = False
        self.post_execute = False
        self.post_common = False
        self.call_id = self.ret_id = None

    def get_const_name(self):
        return drop_prefix(self.name).upper()

    const_name = property(get_const_name)

    def get_call_name(self):
        return "CALL_" + self.get_const_name()

    call_name = property(get_call_name)

    def get_ret_name(self):
        return "RET_" + self.get_const_name()

    ret_name = property(get_ret_name)

    def get_output_args(self):
        return [a
                for a in self.sending_order_args
                if data_of_argument(self, a).out]

    output_args = property(get_output_args)

    def get_input_args(self):
        return [a
                for a in self.sending_order_args
                if not data_of_argument(self, a).out]

    input_args = property(get_input_args)

    def __str__(self):
        args = ", ".join([str(a) for a in self.args])
        fmt = "{rettype} {name}({args})"
        return fmt.format(rettype=self.rettype, name=self.name, args=args)

    __repr__ = __str__

def split_datatype_name(datatype_with_name):
    index = search(r"\w+$", datatype_with_name).start()
    return datatype_with_name[:index].strip(), datatype_with_name[index:]

def parse_formal_arguments(args):
    return [a.strip() for a in args.split(",")] if args != "void" else []

def drop_const(datatype):
    return sub(r"\bconst\b", "", datatype).replace("  ", " ").strip()

def parse_proto(proto):
    assert proto[-2:] == ");"
    lpar = proto.index("(")
    rpar = proto.rindex(")")
    rettype, name = split_datatype_name(proto[:lpar])
    args = parse_formal_arguments(proto[lpar + 1:rpar])

    syscall = Syscall()
    syscall.rettype = drop_const(rettype)
    syscall.name = name
    for a in args:
        datatype, name = split_datatype_name(a)
        syscall.args.append(Variable(drop_const(datatype), name))

    # fsyscall sends arguments in order written in syscalls.master. But some
    # arguments hold size of previous arguments.
    args = syscall.args
    specials = ("fmaster_write", "fmaster_read", "fmaster_writev")
    syscall.sending_order_args = args if syscall.name not in specials else [
            args[0],
            args[2],
            args[1]]

    return syscall

def get_hook_path(dirpath, syscall, fmt):
    return join(dirpath, fmt.format(name=syscall.name))

def get_post_common_path(dirpath, syscall):
    return get_hook_path(dirpath, syscall, "{name}_post_common.c")

def get_post_execute_path(dirpath, syscall):
    return get_hook_path(dirpath, syscall, "{name}_post_execute.c")

def get_pre_execute_path(dirpath, syscall):
    return get_hook_path(dirpath, syscall, "{name}_pre_execute.c")

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

def number_syscalls(syscalls, header):
    with open(header) as fp:
        for line in fp:
            cols = split(r"\s+", line.rstrip())
            if (len(cols) != 3) or (cols[0] != "#define"):
                continue
            which, name = cols[1].split("_", 1)
            assert which in ["CALL", "RET"]
            syscall = find_syscall_of_name(syscalls, name)
            attr = "call_id" if which == "CALL" else "ret_id"
            setattr(syscall, attr, int(cols[2]))

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

def read_syscalls(dirpath, command_dir):
    syscalls = []
    with open(join(dirpath, "syscalls.master")) as fp:
        src = fp.read().replace("\\\n", "")
    for line in src.split("\n"):
        if (line.strip() == "") or (line[0] in (";", "#")):
            continue
        if line.split()[2] != "STD":
            continue
        proto = line[line.index("{") + 1:line.rindex("}")].strip()
        syscall = parse_proto(proto)
        syscall.pre_execute = exists(get_pre_execute_path(dirpath, syscall))
        syscall.post_execute = exists(get_post_execute_path(dirpath, syscall))
        syscall.post_common = exists(get_post_common_path(dirpath, syscall))
        syscalls.append(syscall)

    header = join(command_dir, "code.h")
    number_syscalls(syscalls, header)
    find_unnumbered_syscall(syscalls, header)

    return syscalls

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
