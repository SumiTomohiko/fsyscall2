#!/usr/local/bin/python3.2

from functools import partial
from os.path import basename, dirname, join
from re import search, sub
from sys import argv, exit

SYSCALLS = {
        "fmaster_read": None,
        "fmaster_write": None,
        "fmaster_open": None,
        "fmaster_close": None,
        "fmaster_link": None,
        "fmaster_access": None
        }

class Argument:

    def __init__(self, datatype, name):
        self.datatype = datatype
        self.name = name

    def __str__(self):
        datatype = self.datatype
        space = "" if datatype[-1] == "*" else " "
        name = self.name
        return "{datatype}{space}{name}".format(**locals())

    __repr__ = __str__

class Syscall:

    def __init__(self):
        self.rettype = None
        self.name = None
        self.args = []

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
        syscall.args.append(Argument(drop_const(datatype), name))

    return syscall

class Variable:

    def __init__(self, datatype, name, size=None):
        self.datatype = datatype
        self.name = name
        self.size = size

    def __str__(self):
        datatype = self.datatype
        space = "" if self.datatype[-1] == "*" else " "
        name = self.name
        return "{datatype}{space}{name}".format(**locals())

    __repr__ = __str__

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

def write_syscall(dirpath, syscall):
    BUFSIZE_OF_DATATYPE = {
            "size_t": "FSYSCALL_BUFSIZE_UINT64",
            "void *": "FSYSCALL_BUFSIZE_UINT64",
            "int": "FSYSCALL_BUFSIZE_INT32"
            }

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
        for datatype, fmt, size in (
                (a.datatype, "{name}", None),
                ("char", "{name}_buf", BUFSIZE_OF_DATATYPE[a.datatype]),
                ("int", "{name}_len", None)):
            v = Variable(datatype, fmt.format(name=a.name), size)
            local_vars.append(v)

    name = syscall.name
    with open(join(dirpath, name) + ".c", "w") as fp:
        p = partial(print, end="", file=fp)
        prog = argv[0]
        p("""\
/**
 * THIS FILE WAS GENERATED BY {prog}. DON'T EDIT.
 */
#include <sys/param.h>
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
        print_locals(p, local_vars)
        p("""\

\tpath = uap->path;
\tpath_len = strlen(path);
\tpath_len_len = fsyscall_encode_uint64(
\t\tpath_len,
\t\tpath_len_buf,
\t\tarray_sizeof(path_len_buf));
\tif (path_len_len < 0)
\t\treturn (EMSGSIZE);

\tflags = uap->flags;
\tflags_len = fsyscall_encode_int32(
\t\tflags,
\t\tflags_buf,
\t\tarray_sizeof(flags_buf));
\tif (flags_len < 0)
\t\treturn (EMSGSIZE);

\terror = fmaster_write_command(td, CALL_ACCESS);
\tif (error != 0)
\t\treturn (error);
\tpayload_size = path_len_len + path_len + flags_len;
\terror = fmaster_write_payload_size(td, payload_size);
\tif (error != 0)
\t\treturn (error);
\twfd = fmaster_wfd_of_thread(td);
\terror = fmaster_write(td, wfd, path_len_buf, path_len_len);
\tif (error != 0)
\t\treturn (error);
\terror = fmaster_write(td, wfd, path, path_len);
\tif (error != 0)
\t\treturn (error);
\terror = fmaster_write(td, wfd, flags_buf, flags_len);
\tif (error != 0)
\t\treturn (error);

\treturn (0);
}}

int
sys_{name}(struct thread *td, struct {name}_args *uap)
{{
\tint error;

\terror = execute_call(td, uap);
\tif (error != 0)
\t\treturn (error);
\treturn (fmaster_execute_return_generic(td, RET_ACCESS));
}}""".format(**locals()), file=fp)

def main(dirpath):
    with open(join(dirpath, "syscalls.master")) as fp:
        src = fp.read().replace("\\\n", "")
    for line in src.split("\n"):
        if (line.strip() == "") or (line[0] in (";", "#")):
            continue
        if (line.split()[2] != "STD"):
            continue
        proto = line[line.index("{") + 1:line.rindex("}")].strip()
        syscall = parse_proto(proto)
        if syscall.name not in SYSCALLS:
            continue
        write_syscall(dirpath, syscall)

def usage():
    print("Usage: {prog} dirpath".format(prog=basename(argv[0])))

if __name__ == "__main__":
    main(dirname(__file__) if len(argv) != 2 else argv[1])

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
