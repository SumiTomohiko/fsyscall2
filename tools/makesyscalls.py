#!/usr/local/bin/python3.2

from functools import partial
from os import getcwd, mkdir
from os.path import abspath, basename, dirname, join
from re import search, sub
from sys import argv, exit

def make_decl(o):
    datatype = drop_pointer(o.datatype)
    name = make_local_decl(o)
    return "{datatype} {name}".format(**locals())

class Variable:

    def __init__(self, datatype, name, size=None):
        self.datatype = datatype
        self.name = name
        self.size = size

    __repr__ = __str__ = make_decl

class Struct:

    def __init__(self, members):
        self.members = members

stat = Struct([
    # TODO: Write here.
    ])

class Argument:

    def __init__(self, opt=None, out=False, size=None, struct=None):
        self.opt = opt
        self.out = out
        self.size = size
        self.struct = struct

SYSCALLS = {
        "fmaster_write": {
            "buf": Argument(size="nbytes")
            },
        "fmaster_open": {
            "mode": Argument(opt="(flags & O_CREAT) != 0")
            },
        "fmaster_close": {},
        "fmaster_link": {},
        "fmaster_access": {},
        "fmaster_fstat": {
            "sb": Argument(out=True, struct=stat)
            }
        }
FMASTER_SYSCALLS = SYSCALLS
FSLAVE_SYSCALLS = SYSCALLS

class Syscall:

    def __init__(self):
        self.rettype = None
        self.name = None
        self.args = []
        self.sending_order_args = None

    def __str__(self):
        args = ", ".join([str(a) for a in self.args])
        fmt = "{rettype} {name}({args})"
        return fmt.format(rettype=self.rettype, name=self.name, args=args)

    __repr__ = __str__

def split_datatype_name(datatype_with_name):
    index = search(r"\w+$", datatype_with_name).start()
    return datatype_with_name[:index].strip(), datatype_with_name[index:]

def drop_const(datatype):
    return sub(r"\bconst\b", "", datatype).replace("  ", " ").strip()

def parse_proto(proto):
    assert proto[-2:] == ");"
    lpar = proto.index("(")
    rpar = proto.rindex(")")
    rettype, name = split_datatype_name(proto[:lpar])
    args = [a.strip() for a in proto[lpar + 1:rpar].split(",")]

    syscall = Syscall()
    syscall.rettype = drop_const(rettype)
    syscall.name = name
    for a in args:
        datatype, name = split_datatype_name(a)
        syscall.args.append(Variable(drop_const(datatype), name))

    # fsyscall sends arguments in order written in syscalls.master. But some
    # arguments hold size of previous arguments.
    args = syscall.args
    syscall.sending_order_args = args if syscall.name != "fmaster_write" else [
            args[0],
            args[2],
            args[1]]

    return syscall

def make_string_locals(name):
    a = []
    for datatype, fmt, size in (
            ("char *", "{name}", None),
            ("size_t", "{name}_len", None),
            ("char", "{name}_len_buf", "FSYSCALL_BUFSIZE_UINT64"),
            ("int", "{name}_len_len", None)):
        a.append(Variable(datatype, fmt.format(**locals()), size))
    return a

def drop_pointer(datatype):
    return datatype if datatype[-1] != "*" else datatype[:-2]

def datasize_of_datatype(datatype):
    DATASIZE_OF_DATATYPE = {
            "payload_size_t": 64,
            "size_t": 64,
            "uint64_t": 64,
            "void": 64,
            "int": 32,
            "char": 1
            }
    return DATASIZE_OF_DATATYPE[datatype]

def sort_datatypes(datatypes):
    datatypes_of_datasize = {}
    for datatype in datatypes:
        size = datasize_of_datatype(datatype)
        try:
            datatypes_of_datasize[size].append(datatype)
        except KeyError:
            datatypes_of_datasize[size] = [datatype]
    a = []
    for datasize in sorted(datatypes_of_datasize.keys(), reverse=True):
        a.extend(sorted(datatypes_of_datasize[datasize]))
    return a

def locals_of_datatype(local_vars, datatype):
    return [v for v in local_vars if drop_pointer(v.datatype) == datatype]

def strlen(s):
    return len(s.replace("\t", 8 * " "))

def make_local_decl(local_var):
    ast = "*" if local_var.datatype[-1] == "*" else ""
    name = local_var.name
    make_bracket = lambda: "[{size}]".format(**vars(local_var))
    size = make_bracket() if local_var.size is not None else ""
    return "{ast}{name}{size}".format(**locals())

def print_first_local(p, datatype, local_var):
    decl = make_local_decl(local_var)
    s = "\t{datatype} {decl}".format(**locals())
    p(s)
    return strlen(s)

def print_locals(p, local_vars):
    datatypes = list(set([drop_pointer(v.datatype) for v in local_vars]))
    for datatype in sort_datatypes(datatypes):
        f = lambda v: v.name
        a = sorted(locals_of_datatype(local_vars, datatype), key=f)

        col = print_first_local(p, datatype, a[0])
        CHARS_PER_LINE = 80
        for local_var in a[1:]:
            ast = "*" if local_var.datatype[-1] == "*" else ""
            make_bracket = lambda: "[{size}]".format(**vars(local_var))
            size = make_bracket() if local_var.size is not None else ""
            fmt = ", {ast}{name}{size}"
            s = fmt.format(ast=ast, name=local_var.name, size=size)
            if CHARS_PER_LINE <= col + strlen(s) + 1:
                p(";\n")
                col = print_first_local(p, datatype, local_var)
                continue
            col += strlen(s)
            p(s)
        p(";\n")

def print_caution(p):
    prog = argv[0]
    p("""\
/**
 * THIS FILE WAS GENERATED BY {prog}. DON'T EDIT.
 */
""".format(**locals()))

def print_head(p, name):
    print_caution(p)
    p("""\
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/proc.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_call(struct thread *td, struct {name}_args *uap)
{{
""".format(**locals()))

def concrete_datatype_of_abstract_datatype(datatype):
    return {
            "char *": "uint64",
            "size_t": "uint64",
            "void *": "int64",
            "int": "int32" }[datatype]

def opt_of_syscall(tab, syscall, a):
    try:
        return tab[syscall.name][a.name].opt
    except KeyError:
        return None

def print_encoding(p, syscall):
    for a in syscall.args:
        if a.datatype == "void *":
            continue

        p("\t{name} = uap->{name};\n".format(**vars(a)))
        if a.datatype == "char *":
            p("""\
\t{name}_len = strlen({name});
""".format(name=a.name))
            name = "{name}_len".format(**vars(a))
        else:
            name = a.name
        concrete_datatype = concrete_datatype_of_abstract_datatype(a.datatype)
        opt = opt_of_syscall(FMASTER_SYSCALLS, syscall, a)
        if opt is not None:
            expr_head = "{opt} ? ".format(**locals())
            expr_tail = " : 0"
        else:
            expr_head = expr_tail = ""
        p("""\
\t{name}_len = {expr_head}fsyscall_encode_{concrete_datatype}(
\t\t{name},
\t\t{name}_buf,
\t\tarray_sizeof({name}_buf)){expr_tail};
\tif ({name}_len < 0)
\t\treturn (EMSGSIZE);
""".format(**locals()))

def bufsize_of_datatype(datatype):
    concrete = concrete_datatype_of_abstract_datatype(datatype)
    return "FSYSCALL_BUFSIZE_" + concrete.upper()

def make_payload_size_expr(syscall):
    terms = []
    for a in syscall.args:
        if a.datatype == "void *":
            size = SYSCALLS[syscall.name][a.name].size
            assert size is not None
            terms.append(size)
            continue

        if a.datatype == "char *":
            terms.append("{name}_len_len".format(**vars(a)))
        terms.append("{name}_len".format(**vars(a)))

    return " + ".join(terms)

def print_fmaster_write(p, buf, size):
    p("""\
\terror = fmaster_write(td, wfd, {buf}, {size});
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))

def make_cmd_name(syscall):
    prefix = "fmaster_"
    assert syscall.name[:len(prefix)] == prefix
    return syscall.name[len(prefix):].upper()

def print_write(p, syscall):
    cmd_name = make_cmd_name(syscall)
    payload_size_expr = make_payload_size_expr(syscall)
    p("""\
\terror = fmaster_write_command(td, CALL_{cmd_name});
\tif (error != 0)
\t\treturn (error);
\tpayload_size = {payload_size_expr};
\terror = fmaster_write_payload_size(td, payload_size);
\tif (error != 0)
\t\treturn (error);
\twfd = fmaster_wfd_of_thread(td);
""".format(**locals()))
    for a in syscall.sending_order_args:
        if a.datatype == "char *":
            buf = "{name}_len_buf".format(**vars(a))
            size = "{name}_len_len".format(**vars(a))
            print_fmaster_write(p, buf, size)
            print_fmaster_write(p, a.name, "{name}_len".format(**vars(a)))
            continue
        if a.datatype == "void *":
            name = a.name
            size = SYSCALLS[syscall.name][name].size
            p("""\
\terror = fmaster_write_userspace(td, wfd, uap->{name}, {size});
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))
            continue
        opt = opt_of_syscall(FMASTER_SYSCALLS, syscall, a)
        if opt is not None:
            p("""\
\tif (!({opt}))
\t\treturn (0);
""".format(**locals()))
        buf = "{name}_buf".format(**vars(a))
        size = "{name}_len".format(**vars(a))
        print_fmaster_write(p, buf, size)

def print_tail(p, syscall):
    name = syscall.name
    cmd_name = make_cmd_name(syscall)
    p("""\
\treturn (0);
}}

int
sys_{name}(struct thread *td, struct {name}_args *uap)
{{
\tint error;

\terror = execute_call(td, uap);
\tif (error != 0)
\t\treturn (error);
\treturn (fmaster_execute_return_generic(td, RET_{cmd_name}));
}}
""".format(**locals()))

def partial_print(fp):
    p = partial(print, end="", file=fp)
    return p, partial(p, "\n")

def write_syscall(dirpath, syscall):
    local_vars = []
    for datatype, name in (
            ("payload_size_t", "payload_size"),
            ("int", "error"),
            ("int", "wfd")):
        local_vars.append(Variable(datatype, name))
    for a in syscall.args:
        if a.datatype == "char *":
            local_vars.extend(make_string_locals(a.name))
            continue
        if a.datatype == "void *":
            continue
        for datatype, fmt, size in (
                (a.datatype, "{name}", None),
                ("char", "{name}_buf", bufsize_of_datatype(a.datatype)),
                ("int", "{name}_len", None)):
            v = Variable(datatype, fmt.format(name=a.name), size)
            local_vars.append(v)

    name = syscall.name
    with open(join(dirpath, name) + ".c", "w") as fp:
        p, print_newline = partial_print(fp)
        print_head(p, name)
        print_locals(p, local_vars)
        print_newline()
        print_encoding(p, syscall)
        print_newline()
        print_write(p, syscall)
        print_newline()
        print_tail(p, syscall)

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
        syscalls.append(parse_proto(proto))
    return syscalls

def write_fmaster(dirpath, syscalls):
    for syscall in [sc for sc in syscalls if sc.name in FMASTER_SYSCALLS]:
        write_syscall(dirpath, syscall)

def drop_prefix(s):
    return s[s.find("_") + 1:]

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

def print_fslave_head(p, syscall):
    name = drop_prefix(syscall.name)
    print_caution(p)
    p("""\
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/fslave.h>
#include <fsyscall/private/io.h>

static void
execute_{name}(struct slave *slave, int *ret, int *errnum)
{{
""".format(**locals()))

def make_fslave_payload_size_expr(syscall):
    terms = []
    for a in syscall.args:
        if a.datatype == "void *":
            terms.append(SYSCALLS[syscall.name][a.name].size)
            continue
        terms.append("{name}_len".format(**vars(a)))
    return " + ".join(terms)

def print_fslave_main(p, print_newline, syscall):
    local_vars = []
    for datatype, name in (
            ("payload_size_t", "payload_size"),
            ("payload_size_t", "actual_payload_size"),
            ("int", "rfd")):
        local_vars.append(Variable(datatype, name))
    for a in syscall.args:
        if a.datatype == "void *":
            local_vars.append(Variable(a.datatype, a.name))
            continue
        len_type = "uint64_t" if a.datatype == "char *" else "int"
        for datatype, name in (
                (len_type, "{name}_len"),
                ("{datatype}", "{name}")):
            d = vars(a)
            v = Variable(datatype.format(**d), name.format(**d))
            local_vars.append(v)

    print_locals(p, local_vars)
    print_newline()
    p("""\
\trfd = slave->rfd;
\tpayload_size = read_payload_size(rfd);
""")
    print_newline()
    for a in syscall.sending_order_args:
        name = a.name
        if a.datatype == "void *":
            size = SYSCALLS[syscall.name][name].size
            p("""\
\t{name} = alloca({size});
\tread_or_die(rfd, {name}, {size});
""".format(**locals()))
            continue

        f = {
                "char *": "read_string",
                "int": "read_int32",
                "size_t": "read_uint64" }[a.datatype]
        assignment = "{name} = {f}(rfd, &{name}_len)".format(**locals())
        opt = opt_of_syscall(FMASTER_SYSCALLS, syscall, a)
        if opt is not None:
            p("""\
\tif ({opt})
\t\t{assignment};
\telse
\t\t{name} = {name}_len = 0;
""".format(**locals()))
        else:
            p("""\
\t{assignment};
""".format(**locals()))
    print_newline()
    payload_size = make_fslave_payload_size_expr(syscall)
    name = drop_prefix(syscall.name)
    args = ", ".join([a.name for a in syscall.args])
    p("""\
\tactual_payload_size = {payload_size};
\tdie_if_payload_size_mismatched(payload_size, actual_payload_size);

\t*ret = {name}({args});
\t*errnum = errno;
""".format(**locals()))
    for a in syscall.args:
        if a.datatype != "char *":
            continue
        p("""\
\tfree({name});
""".format(**vars(a)))

def print_fslave_tail(p, syscall):
    name = drop_prefix(syscall.name)
    cmd_name = name.upper()
    p("""\
}}

void
process_{name}(struct slave *slave)
{{
\tint errnum, ret;

\texecute_{name}(slave, &ret, &errnum);
\treturn_generic(slave, RET_{cmd_name}, ret, errnum);
}}
""".format(**locals()))

def write_fslave(dirpath, syscalls):
    for syscall in [sc for sc in syscalls if sc.name in FSLAVE_SYSCALLS]:
        name = drop_prefix(syscall.name)
        path = join(dirpath, "fslave_{name}.c".format(**locals()))
        with open(path, "w") as fp:
            p, print_newline = partial_print(fp)
            print_fslave_head(p, syscall)
            print_fslave_main(p, print_newline, syscall)
            print_fslave_tail(p, syscall)

def write_makefile(path, syscalls):
    with open(path, "w") as fp:
        p, _ = partial_print(fp)
        p("SRCS+=\t")

        fmt = "{name}.c"
        files = []
        for syscall in syscalls:
            if syscall.name not in FSLAVE_SYSCALLS:
                continue
            name = "fslave_{name}.c".format(name=drop_prefix(syscall.name))
            files.append(name)
        p(" ".join(files))

def write_proto(dirpath, syscalls):
    try:
        mkdir(dirpath)
    except OSError:
        pass
    with open(join(dirpath, "proto.h"), "w") as fp:
        p, print_newline = partial_print(fp)
        print_caution(p)
        p("""\
#if !defined(FSYSCALL_PRIVATE_FSLAVE_PROTO_H_INCLUDED)
#define FSYSCALL_PRIVATE_FSLAVE_PROTO_H_INCLUDED
""")
        print_newline()
        for syscall in syscalls:
            if syscall.name not in FSLAVE_SYSCALLS:
                continue
            p("""\
void process_{name}(struct slave *);
""".format(name=drop_prefix(syscall.name)))
        print_newline()
        p("""\
#endif
""")

def main(dirpath):
    fmaster_dir = join(dirpath, "fmaster", "sys", "fmaster")
    syscalls = read_syscalls(fmaster_dir)
    write_fmaster(fmaster_dir, syscalls)

    private_dir = join(dirpath, "include", "fsyscall", "private")
    command_dir = join(private_dir, "command")
    write_command(command_dir, syscalls)

    fslave_dir = join(dirpath, "fslave")
    write_fslave(fslave_dir, syscalls)

    write_makefile(join(fslave_dir, "Makefile.makesyscalls"), syscalls)
    write_proto(join(private_dir, "fslave"), syscalls)

def usage():
    print("usage: {prog} dirpath".format(prog=basename(argv[0])))

if __name__ == "__main__":
    main(abspath(getcwd()) if len(argv) != 2 else argv[1])

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
