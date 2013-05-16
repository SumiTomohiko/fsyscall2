
from os.path import exists, join
from re import search, sub

from fsyscall.share import Variable, drop_prefix

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

def number_syscalls(syscalls):
    n = 42
    for syscall in syscalls:
        syscall.call_id = n
        syscall.ret_id = n + 1
        n += 2

def read_syscalls(dirpath):
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

    number_syscalls(syscalls)

    return syscalls

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
