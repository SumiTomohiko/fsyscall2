#!/usr/local/bin/python3

from functools import partial
from os import getcwd, mkdir
from os.path import abspath, basename, dirname, exists, join
from re import compile, search, sub
from sys import argv, exit

RE_ARRAY_DATATYPE = compile(r"^(?P<type>.+) \(\*\)\[(?P<size>.+)\]$")

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
    Variable("__dev_t", "st_dev"),
    Variable("ino_t", "st_ino"),
    Variable("mode_t", "st_mode"),
    Variable("nlink_t", "st_nlink"),
    Variable("uid_t", "st_uid"),
    Variable("gid_t", "st_gid"),
    Variable("__dev_t", "st_rdev"),
    #Variable("struct timespec", "st_atim"),
    #Variable("struct timespec", "st_mtim"),
    #Variable("struct timespec", "st_ctim"),
    Variable("off_t", "st_size"),
    Variable("blkcnt_t", "st_blocks"),
    Variable("blksize_t", "st_blksize"),
    Variable("fflags_t", "st_flags"),
    Variable("__uint32_t", "st_gen"),
    Variable("__int32_t", "st_lspare"),
    #Variable("struct timespec", "st_birthtim")
    ])

class Argument:

    def __init__(self, opt=None, out=False, size=None, retsize=None, struct=None):
        self.opt = opt
        self.out = out
        self.size = size
        self.retsize = retsize
        self.struct = struct

SYSCALLS = {
        "fmaster_read": {
            "buf": Argument(out=True, size="nbytes", retsize="retval")
            },
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
            },
        "fmaster_lstat": {
            "ub": Argument(out=True, struct=stat)
            },
        "fmaster_stat": {
            "ub": Argument(out=True, struct=stat)
            },
        "fmaster_issetugid": {},
        "fmaster_lseek": {},
        "fmaster_pread": {
            "buf": Argument(out=True, size="nbyte", retsize="retval")
            },
        "fmaster_readlink": {
            "buf": Argument(out=True, size="count", retsize="retval")
            },
        "fmaster_writev": {
            "iovp": Argument(size="iovcnt")
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
        self.pre_execute = False
        self.post_execute = False

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

def parse_formal_arguments(args):
    return [a.strip() for a in args.split(",")] if args != "void" else []

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

def size_of_bufsize(name):
    m = search(r"\d+$", name)
    assert m is not None
    return int(m.group()) // 7 + 1

def datasize_of_datatype(datatype):
    if datatype.split()[0] == "struct":
        return 64
    DATASIZE_OF_DATATYPE = {
            "u_int": 32,
            "__dev_t": 32,
            "__int32_t": 32,
            "__uint32_t": 32,
            "blkcnt_t": 64,
            "blksize_t": 32,
            "char": 1,
            "command_t": 32,
            "fflags_t": 32,
            "gid_t": 32,
            "ino_t": 32,
            "int": 32,
            "int64_t": 64,
            "mode_t": 16,
            "nlink_t": 16,
            "off_t": 64,
            "payload_size_t": 64,
            "size_t": 64,
            "ssize_t": 64,
            "uid_t": 32,
            "uint64_t": 64,
            "void": 64
            }
    m = RE_ARRAY_DATATYPE.match(datatype)
    if m is None:
        return DATASIZE_OF_DATATYPE[datatype]
    base = DATASIZE_OF_DATATYPE[m.group("type")]
    return 8 * base * size_of_bufsize(m.group("size"))

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
    if RE_ARRAY_DATATYPE.match(datatype):
        pos = datatype.find("*")
        s = "\t" + datatype[:pos + 1] + local_var.name + datatype[pos + 1:]
        p(s)
        return strlen(s)
    decl = make_local_decl(local_var)
    s = "\t{datatype} {decl}".format(**locals())
    p(s)
    return strlen(s)

LINE_WIDTH = 80

def print_locals(p, local_vars):
    datatypes = list(set([drop_pointer(v.datatype) for v in local_vars]))
    for datatype in sort_datatypes(datatypes):
        f = lambda v: v.name
        a = sorted(locals_of_datatype(local_vars, datatype), key=f)

        col = print_first_local(p, datatype, a[0])
        for local_var in a[1:]:
            # This part cannot handle datatype such as
            # "char (*)[FSYSCALL_BUFSIZE_UINT64]". But no system call has more
            # than one arguments of "struct iovec *". So it will not get
            # problem.
            ast = "*" if local_var.datatype[-1] == "*" else ""
            make_bracket = lambda: "[{size}]".format(**vars(local_var))
            size = make_bracket() if local_var.size is not None else ""
            fmt = ", {ast}{name}{size}"
            s = fmt.format(ast=ast, name=local_var.name, size=size)
            if LINE_WIDTH <= col + strlen(s) + 1:
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
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_call(struct thread *td, struct {name}_args *uap)
{{
""".format(**locals()))

def concrete_datatype_of_abstract_datatype(datatype):
    return {
            "u_int": "uint32",
            "__dev_t": "uint32",
            "__int32_t": "int32",
            "__uint32_t": "uint32",
            "blkcnt_t": "int64",
            "blksize_t": "uint32",
            "fflags_t": "uint32",
            "gid_t": "uint32",
            "ino_t": "uint32",
            "int64_t": "int64",
            "mode_t": "uint16",
            "nlink_t": "uint16",
            "off_t": "int64",
            "uid_t": "uint32",
            "uint64_t": "uint64",
            "char *": "uint64",
            "size_t": "uint64",
            "ssize_t": "int64",
            "void *": "int64",
            "int": "int32" }[datatype]

def opt_of_syscall(tab, syscall, a):
    try:
        return tab[syscall.name][a.name].opt
    except KeyError:
        return None

def print_encoding(p, syscall):
    for a in syscall.sending_order_args:
        if (a.datatype == "void *") or data_of_argument(syscall, a).out:
            continue

        p("\t{name} = uap->{name};\n".format(**vars(a)))
        if a.datatype == "struct iovec *":
            concrete_datatype = concrete_datatype_of_abstract_datatype("size_t")
            size = data_of_argument(syscall, a).size
            name = a.name
            p("""\
\t{name}_iov_len_buf = (char (*)[FSYSCALL_BUFSIZE_UINT64])malloc(
\t\tsizeof(char [FSYSCALL_BUFSIZE_UINT64]) * {size},
\t\tM_TEMP,
\t\tM_WAITOK);
\t{name}_iov_len_len = (int *)malloc(
\t\tsizeof(u_int) * iovcnt,
\t\tM_TEMP,
\t\tM_WAITOK);
\tfor (i = 0; i < iovcnt; i++) {{
\t\t{name}_iov_len_len[i] = fsyscall_encode_{concrete_datatype}(
\t\t\t{name}[i].iov_len,
\t\t\t{name}_iov_len_buf[i],
\t\t\tarray_sizeof({name}_iov_len_buf[i]));
\t\tif ({name}_iov_len_len[i] < 0)
\t\t\treturn (EMSGSIZE);
\t}}
""".format(**locals()))
            continue

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

def make_payload_size_expr(syscall, args, bufsize="size"):
    if len(args) == 0:
        return "0"

    terms = []
    for a in args:
        if (a.datatype == "void *") or ((a.datatype == "char *") and data_of_argument(syscall, a).out):
            size = getattr(SYSCALLS[syscall.name][a.name], bufsize)
            assert size is not None
            terms.append(size)
            continue

        st = data_of_argument(syscall, a).struct
        if st is not None:
            struct_name = a.name
            for member in st.members:
                name = member.name
                terms.append("{struct_name}_{name}_len".format(**locals()))
            continue

        if a.datatype == "struct iovec *":
            terms.append("{name}_payload_size".format(**vars(a)))
            continue

        if a.datatype == "char *":
            assert not data_of_argument(syscall, a).out
            # Input arguments of char * include their size using NUL terminator
            # (any other arguments do not hold their size). So it need one more
            # special variable.
            terms.append("{name}_len_len".format(**vars(a)))
        terms.append("{name}_len".format(**vars(a)))

    return " + ".join(terms)

def print_fmaster_write(p, buf, size, indent=1):
    tabs = indent * "\t"
    p("""\
{tabs}error = fmaster_write(td, wfd, {buf}, {size});
{tabs}if (error != 0)
{tabs}\treturn (error);
""".format(**locals()))

def make_cmd_name(name):
    prefix = "fmaster_"
    assert name[:len(prefix)] == prefix
    return name[len(prefix):].upper()

def input_arguments_of_syscall(syscall):
    return [a for a in syscall.args if not data_of_argument(syscall, a).out]

def print_write(p, print_newline, syscall):
    cmd_name = make_cmd_name(syscall.name)
    p("""\
\terror = fmaster_write_command(td, CALL_{cmd_name});
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))

    input_arguments = input_arguments_of_syscall(syscall)
    for a in [a for a in input_arguments if a.datatype == "struct iovec *"]:
        name = a.name
        size = data_of_argument(syscall, a).size
        p("""\
\t{name}_payload_size = 0;
\tfor (i = 0; i < {size}; i++)
\t\t{name}_payload_size += {name}_iov_len_len[i] + {name}[i].iov_len;
""".format(**locals()))

    payload_size_expr = make_payload_size_expr(syscall, input_arguments)
    p("""\
\tpayload_size = {payload_size_expr};
\terror = fmaster_write_payload_size(td, payload_size);
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))
    if len(input_arguments) == 0:
        return

    p("""\
\twfd = fmaster_wfd_of_thread(td);
""".format(**locals()))
    for a in syscall.sending_order_args:
        if data_of_argument(syscall, a).out:
            continue

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
\terror = fmaster_write_from_userspace(td, wfd, uap->{name}, {size});
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))
            continue

        if a.datatype == "struct iovec *":
            p("""\
\tfor (i = 0; i < iovcnt; i++) {{
""".format(**locals()))

            buf = "{name}_iov_len_buf[i]".format(**vars(a))
            size = "{name}_iov_len_len[i]".format(**vars(a))
            print_fmaster_write(p, buf, size, 2)

            buf = "{name}[i].iov_base".format(**vars(a))
            size = "{name}[i].iov_len".format(**vars(a))
            print_fmaster_write(p, buf, size, 2)

            p("""\
\t}}
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

    cleanup_args = [
            a
            for a in syscall.sending_order_args
            if a.datatype == "struct iovec *"]
    if len(cleanup_args) == 0:
        return
    print_newline()
    for a in cleanup_args:
        p("""\
\tfree({name}_iov_len_len, M_TEMP);
\tfree({name}_iov_len_buf, M_TEMP);
""".format(**vars(a)))

def print_call_tail(p, print_newline):
    p("""\
\treturn (0);
}
""")
    print_newline()

def print_master_call(p, print_newline, syscall):
    if len([a for a in syscall.args if a.name == "fd"]) == 0:
        return
    name = drop_prefix(syscall.name)
    p("""\
\tif (fmaster_type_of_fd(td, uap->fd) == fft_master) {{
\t\tstruct {name}_args a;
\t\tint *fds = fmaster_fds_of_thread(td);
\t\tmemcpy(&a, uap, sizeof(a));
\t\ta.fd = LOCAL_FD(fds[uap->fd]);
\t\treturn (sys_{name}(td, &a));
\t}}
""".format(**locals()))
    print_newline()

def print_generic_tail(p, print_newline, syscall):
    print_call_tail(p, print_newline)

    local_vars = [Variable("int", "error")]
    name = syscall.name
    p("""\
int
sys_{name}(struct thread *td, struct {name}_args *uap)
{{
""".format(**locals()))
    print_locals(p, local_vars)
    print_newline()
    print_master_call(p, print_newline, syscall)
    if syscall.pre_execute:
        p("""\
\tif ({name}_pre_execute(td, uap, &error) == 0)
\t\treturn (error);
""".format(**locals()))
        print_newline()
    cmd_name = make_cmd_name(name)
    p("""\
\terror = execute_call(td, uap);
\tif (error != 0)
\t\treturn (error);
\terror = fmaster_execute_return_generic(td, RET_{cmd_name});
""".format(**locals()))
    if syscall.post_execute:
        p("""\
\tif (error != 0)
\t\treturn (error);

\terror = {name}_post_execute(td, uap);
""".format(**locals()))
    p("""\
\treturn (error);
}}
""".format(**locals()))

def out_arguemnts_of_syscall(syscall):
    return [a for a in syscall.args if data_of_argument(syscall, a).out]

def print_execute_return(p, print_newline, syscall):
    name = syscall.name
    p("""\
static int
execute_return(struct thread *td, struct {name}_args *uap)
{{
""".format(**locals()))

    local_vars = []
    for datatype, name in (
            ("command_t", "cmd"),
            ("int", "errnum"),
            ("int", "errnum_len"),
            ("int", "error"),
            ("int", "retval_len"),
            ("int", "rfd"),
            ("payload_size_t", "expected_payload_size"),
            ("payload_size_t", "payload_size"),
            (syscall.rettype, "retval")):
        local_vars.append(Variable(datatype, name))
    out_arguments = out_arguemnts_of_syscall(syscall)
    for a in out_arguments:
        if a.datatype in ("char *", "void *"):
            continue
        st = data_of_argument(syscall, a).struct
        if st is not None:
            local_vars.append(Variable(a.datatype, a.name))
            for datatype, name in (
                    ("int", "{name}_len"),
                    ("{datatype}", "{name}")):
                for member in st.members:
                    s = "{arg}_{member}".format(arg=a.name, member=member.name)
                    d = { "datatype": member.datatype, "name": s }
                    t = datatype.format(**d)
                    n = name.format(**d)
                    local_vars.append(Variable(t, n))
            continue
        for datatype, name in (("int", "{name}_len"), ("{datatype}", "{name}")):
            d = vars(a)
            t = datatype.format(**d)
            n = name.format(**d)
            local_vars.append(Variable(t, n))
    print_locals(p, local_vars)
    print_newline()

    cmd_name = make_cmd_name(syscall.name)
    t = concrete_datatype_of_abstract_datatype(syscall.rettype)
    p("""\
\terror = fmaster_read_command(td, &cmd);
\tif (error != 0)
\t\treturn (error);
\tif (cmd != RET_{cmd_name})
\t\treturn (EPROTO);
\terror = fmaster_read_payload_size(td, &payload_size);
\tif (error != 0)
\t\treturn (error);
\terror = fmaster_read_{t}(td, &retval, &retval_len);
\tif (error != 0)
\t\treturn (error);
\tif (retval == -1) {{
\t\terror = fmaster_read_int32(td, &errnum, &errnum_len);
\t\tif (error != 0)
\t\t\treturn (error);
\t\tif (retval_len + errnum_len != payload_size)
\t\t\treturn (EPROTO);
\t\treturn (errnum);
\t}}
""".format(**locals()))
    print_newline()
    p("""\
\trfd = fmaster_rfd_of_thread(td);
""")

    for a in out_arguments:
        if a.datatype in ("char *", "void *"):
            p("""\
\terror = fmaster_read_to_userspace(td, rfd, uap->{name}, {size});
\tif (error != 0)
\t\treturn (error);
""".format(name=a.name, size=data_of_argument(syscall, a).retsize))
            continue
        st = data_of_argument(syscall, a).struct
        if st is not None:
            struct_name = a.name
            p("""\
\t{struct_name} = uap->{struct_name};
""".format(**locals()))
            for member in st.members:
                t = concrete_datatype_of_abstract_datatype(member.datatype)
                name = member.name
                var = "{struct_name}_{name}".format(**locals())
                p("""\
\terror = fmaster_read_{t}(td, &{var}, &{var}_len);
\tif (error != 0)
\t\treturn (error);
\t{struct_name}->{name} = {var};
""".format(**locals()))
    print_newline()

    expected_payload_size = make_payload_size_expr(syscall, out_arguments, "retsize")
    p("""\
\texpected_payload_size = retval_len + {expected_payload_size};
\tif (expected_payload_size != payload_size)
\t\treturn (EPROTO);

\ttd->td_retval[0] = retval;
\treturn (0);
}}
""".format(**locals()))

def print_syscall(p, print_newline, syscall):
    name = syscall.name
    p("""\
int
sys_{name}(struct thread *td, struct {name}_args *uap)
{{
\tint error;
""".format(**locals()))
    print_newline()
    print_master_call(p, print_newline, syscall)
    p("""\
\terror = execute_call(td, uap);
\tif (error != 0)
\t\treturn (error);
\treturn (execute_return(td, uap));
}}
""".format(**locals()))

def print_tail(p, print_newline, syscall):
    if len([a for a in syscall.args if data_of_argument(syscall, a).out]) == 0:
        print_generic_tail(p, print_newline, syscall)
        return
    print_call_tail(p, print_newline)
    print_execute_return(p, print_newline, syscall)
    print_newline()
    print_syscall(p, print_newline, syscall)

def partial_print(fp):
    p = partial(print, end="", file=fp)
    return p, partial(p, "\n")

DEFAULT_ARGUMENT = Argument()

def data_of_argument(syscall, a):
    try:
        return SYSCALLS[syscall.name][a.name]
    except KeyError:
        return DEFAULT_ARGUMENT

def write_syscall(dirpath, syscall):
    local_vars = []
    for datatype, name in (
            ("payload_size_t", "payload_size"),
            ("int", "error")):
        local_vars.append(Variable(datatype, name))
    if 0 < len(syscall.args):
        for datatyoe, name in (("int", "wfd"), ):
            local_vars.append(Variable(datatype, name))
    for a in syscall.args:
        if (a.datatype == "void *") or data_of_argument(syscall, a).out:
            continue
        if a.datatype == "char *":
            local_vars.extend(make_string_locals(a.name))
            continue
        if a.datatype == "struct iovec *":
            local_vars.append(Variable(a.datatype, a.name))
            local_vars.append(Variable("u_int", "i"))
            name = "{name}_payload_size".format(**vars(a))
            local_vars.append(Variable("payload_size_t", name))

            size = bufsize_of_datatype("size_t")
            datatype = "char (*)[{size}]".format(**locals())
            name = "{name}_iov_len_buf".format(name=a.name)
            local_vars.append(Variable(datatype, name))

            name = "{name}_iov_len_len".format(name=a.name)
            local_vars.append(Variable("int *", name))
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
        if 0 < len(syscall.args):
            print_newline()
        print_write(p, print_newline, syscall)
        print_newline()
        print_tail(p, print_newline, syscall)

def get_post_execute_path(dirpath, syscall):
    return join(dirpath, "{name}_post_execute.c".format(name=syscall.name))

def get_pre_execute_path(dirpath, syscall):
    return join(dirpath, "{name}_pre_execute.c".format(name=syscall.name))

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
        syscalls.append(syscall)
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

def make_execute_call_format_argument(a):
    datatype = a.datatype
    space = "" if datatype[-1] == "*" else " "
    name = a.name
    return "{datatype}{space}*{name}".format(**locals())

def print_fslave_head(p, syscall):
    args = ["struct slave *slave", "int *retval", "int *errnum"]
    for a in out_arguemnts_of_syscall(syscall):
        st = data_of_argument(syscall, a).struct
        if st is not None:
            args.append("{datatype}{name}".format(**vars(a)))
            continue
        args.append(make_execute_call_format_argument(a))

    name = drop_prefix(syscall.name)
    print_caution(p)
    p("""\
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fslave.h>
#include <fsyscall/private/io.h>

static void
execute_call({args})
{{
""".format(args=", ".join(args)))

def make_fslave_payload_size_expr(syscall):
    if len(syscall.args) == 0:
        return "0"

    terms = []
    for a in syscall.args:
        if data_of_argument(syscall, a).out:
            continue

        if a.datatype == "void *":
            terms.append(SYSCALLS[syscall.name][a.name].size)
            continue

        if a.datatype == "struct iovec *":
            terms.append("{name}_payload_size".format(**vars(a)))
            continue

        terms.append("{name}_len".format(**vars(a)))

    return " + ".join(terms)

def print_fslave_call(p, print_newline, syscall):
    local_vars = []
    for datatype, name in (
            ("payload_size_t", "payload_size"),
            ("payload_size_t", "actual_payload_size"),
            ("int", "rfd")):
        local_vars.append(Variable(datatype, name))
    input_arguments = input_arguments_of_syscall(syscall)
    for a in input_arguments:
        if a.datatype == "void *":
            local_vars.append(Variable(a.datatype, a.name))
            continue

        if a.datatype == "struct iovec *":
            for datatype, name in (
                    (a.datatype, a.name),
                    ("int *", "{name}_iov_len_len"),
                    ("int", "i"),
                    ("payload_size_t", "{name}_payload_size")):
                local_vars.append(Variable(datatype, name.format(**vars(a))))
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
        if data_of_argument(syscall, a).out:
            continue
        name = a.name
        if a.datatype == "void *":
            size = SYSCALLS[syscall.name][name].size
            p("""\
\t{name} = alloca({size});
\tread_or_die(rfd, {name}, {size});
""".format(**locals()))
            continue

        if a.datatype == "struct iovec *":
            name = a.name
            size = data_of_argument(syscall, a).size
            p("""\
\t{name} = (struct iovec *)alloca(sizeof(*{name}) * {size});
\t{name}_iov_len_len = (int *)alloca(sizeof(int) * {size});
\tfor (i = 0; i < {size}; i++) {{
\t\t{name}[i].iov_len = read_uint64(rfd, &{name}_iov_len_len[i]);
\t\t{name}[i].iov_base = alloca({name}[i].iov_len);
\t\tread_or_die(rfd, {name}[i].iov_base, {name}[i].iov_len);
\t}}
""".format(**locals()))
            continue

        f = {
                "char *": "read_string",
                "int": "read_int32",
                "u_int": "read_uint32",
                "off_t": "read_int64",
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
    if 0 < len(syscall.args):
        print_newline()

    for a in [a for a in input_arguments if a.datatype == "struct iovec *"]:
        name = a.name
        size = data_of_argument(syscall, a).size
        p("""\
\t{name}_payload_size = 0;
\tfor (i = 0; i < {size}; i++)
\t\t{name}_payload_size += {name}_iov_len_len[i] + {name}[i].iov_len;
""".format(**locals()))
        continue

    payload_size = make_fslave_payload_size_expr(syscall)
    p("""\
\tactual_payload_size = {payload_size};
\tdie_if_payload_size_mismatched(payload_size, actual_payload_size);
""".format(**locals()))
    print_newline()

    malloced = False
    out_arguments = out_arguemnts_of_syscall(syscall)
    for a in out_arguments:
        if a.datatype not in ("char *", "void *"):
            continue
        name = a.name
        datatype = a.datatype
        size = data_of_argument(syscall, a).size
        p("""\
\t*{name} = ({datatype})malloc({size});
""".format(**locals()))
        malloced = True
    if malloced:
        print_newline()

    args = []
    for a in syscall.args:
        data = data_of_argument(syscall, a)
        ast = "*" if data.out and (data.struct is None) else ""
        args.append("{ast}{name}".format(ast=ast, name=a.name))
    p("""\
\t*retval = {name}({args});
\t*errnum = errno;
""".format(name=drop_prefix(syscall.name), args=", ".join(args)))

    for a in syscall.args:
        if (a.datatype != "char *") or data_of_argument(syscall, a).out:
            continue
        p("""\
\tfree({name});
""".format(**vars(a)))
    p("""\
}}
""".format(**locals()))

def make_execute_return_actual_arguments(syscall, args):
    exprs = []
    for a in args:
        st = data_of_argument(syscall, a).struct
        fmt = "&{name}" if st is not None else "{name}"
        exprs.append(fmt.format(**vars(a)))
    return ", ".join(exprs)

def get_fslave_return_func(syscall):
    return "return_int" if syscall.rettype == "int" else "return_ssize"

def print_fslave_main(p, print_newline, syscall):
    name = drop_prefix(syscall.name)
    p("""\
void
process_{name}(struct slave *slave)
{{
""".format(**locals()))

    local_vars = []
    for datatype, name in (("int", "retval"), ("int", "errnum")):
        local_vars.append(Variable(datatype, name))

    out_arguments = out_arguemnts_of_syscall(syscall)
    if len(out_arguments) == 0:
        cmd_name = make_cmd_name(syscall.name)
        print_locals(p, local_vars)
        print_newline()
        return_func = get_fslave_return_func(syscall)
        p("""\
\texecute_call(slave, &retval, &errnum);
\t{return_func}(slave, RET_{cmd_name}, retval, errnum);
}}
""".format(**locals()))
        return

    for a in out_arguments:
        st = data_of_argument(syscall, a).struct
        datatype = drop_pointer(a.datatype) if st is not None else a.datatype
        local_vars.append(Variable(datatype, a.name))

    print_locals(p, local_vars)
    print_newline()
    call_args = ", ".join(["&{name}".format(**vars(a)) for a in out_arguments])
    ret_args = make_execute_return_actual_arguments(syscall, out_arguments)
    p("""\
\texecute_call(slave, &retval, &errnum, {call_args});
\texecute_return(slave, retval, errnum, {ret_args});
}}
""".format(**locals()))

def print_fslave_return(p, print_newline, syscall):
    args = ", ".join([make_decl(a) for a in out_arguemnts_of_syscall(syscall)])
    p("""\
static void
execute_return(struct slave *slave, int retval, int errnum, {args})
{{
""".format(**locals()))

    local_vars = [Variable(datatype, name, size) for datatype, name, size in (
        ("payload_size_t", "payload_size", None),
        ("char", "retval_buf", bufsize_of_datatype(syscall.rettype)),
        ("int", "retval_len", None),
        ("int", "wfd", None))]
    out_arguments = out_arguemnts_of_syscall(syscall)
    for a in out_arguments:
        datatype = a.datatype
        if a.datatype in ("char *", "void *"):
            continue
        st = data_of_argument(syscall, a).struct
        assert st is not None
        for member in st.members:
            append = local_vars.append
            fmt = "{struct_name}_{name}_len"
            struct_name = a.name
            name = member.name
            append(Variable("int", fmt.format(**locals())))

            fmt = "{struct_name}_{name}_buf"
            size = bufsize_of_datatype(member.datatype)
            append(Variable("char", fmt.format(**locals()), size))

    print_locals(p, local_vars)
    print_newline()
    cmd_name = make_cmd_name(syscall.name)
    return_func = get_fslave_return_func(syscall)
    p("""\
\tif (retval == -1) {{
\t\t{return_func}(slave, RET_{cmd_name}, retval, errnum);
\t\treturn;
\t}}
""".format(**locals()))
    print_newline()
    p("""\
\tretval_len = encode_{datatype}(retval, retval_buf, array_sizeof(retval_buf));
""".format(datatype=concrete_datatype_of_abstract_datatype(syscall.rettype)))
    for a in out_arguments:
        if a.datatype in ("char *", "void *"):
            continue
        st = data_of_argument(syscall, a).struct
        assert st is not None
        for member in st.members:
            struct_name = a.name
            name = member.name
            datatype = concrete_datatype_of_abstract_datatype(member.datatype)
            p("""\
\t{struct_name}_{name}_len = encode_{datatype}({struct_name}->{name}, {struct_name}_{name}_buf, array_sizeof({struct_name}_{name}_buf));
""".format(**locals()))
    payload_size = make_payload_size_expr(syscall, out_arguments, "retsize")
    p("""\
\tpayload_size = retval_len + {payload_size};

\twfd = slave->wfd;
\twrite_command(wfd, RET_{cmd_name});
\twrite_payload_size(wfd, payload_size);
\twrite_or_die(wfd, retval_buf, retval_len);
""".format(**locals()))
    for a in out_arguments:
        if a.datatype in ("char *", "void *"):
            name = a.name
            size = data_of_argument(syscall, a).retsize
            p("""\
\twrite_or_die(wfd, {name}, {size});
""".format(**locals()))
            continue
        st = data_of_argument(syscall, a).struct
        assert st is not None
        for member in st.members:
            fmt = "{struct_name}_{name}"
            p("""\
\twrite_or_die(wfd, {name}_buf, {name}_len);
""".format(name=fmt.format(struct_name=a.name, name=member.name)))

    newlined = False
    for a in out_arguments:
        st = data_of_argument(syscall, a).struct
        if st is not None:
            continue
        if not newlined:
            print_newline()
            newlined = True
        p("""\
\tfree({name});
""".format(**vars(a)))
    p("""\
}}
""".format(**locals()))

def write_fslave(dirpath, syscalls):
    for syscall in [sc for sc in syscalls if sc.name in FSLAVE_SYSCALLS]:
        name = drop_prefix(syscall.name)
        path = join(dirpath, "fslave_{name}.c".format(**locals()))
        with open(path, "w") as fp:
            p, print_newline = partial_print(fp)
            print_fslave_head(p, syscall)
            print_fslave_call(p, print_newline, syscall)
            print_newline()
            if 0 < len(out_arguemnts_of_syscall(syscall)):
                print_fslave_return(p, print_newline, syscall)
                print_newline()
            print_fslave_main(p, print_newline, syscall)

def pickup_sources(syscalls, prefix):
    srcs = []

    a = [syscall for syscall in syscalls if syscall.name in FSLAVE_SYSCALLS]
    for syscall in a:
        name = drop_prefix(syscall.name)
        srcs.append("{prefix}{name}.c".format(**locals()))

    return srcs

def write_makefile(path, srcs):
    s = "SRCS+=\t"
    pos = 8

    for src in sorted(srcs):
        if LINE_WIDTH - 1 < pos + len(src):
            s += "\\\n\t"
            pos = 8
        t = "{src} ".format(**locals())
        s += t
        pos += len(t)

    with open(path, "w") as fp:
        print(s.strip(), file=fp)

def write_fmaster_makefile(path, syscalls):
    srcs = pickup_sources(syscalls, "fmaster_")

    for syscall in [syscall for syscall in syscalls if syscall.pre_execute]:
        name = syscall.name
        srcs.append("{name}_pre_execute.c".format(**locals()))
    for syscall in [syscall for syscall in syscalls if syscall.post_execute]:
        name = syscall.name
        srcs.append("{name}_post_execute.c".format(**locals()))

    write_makefile(path, srcs)

def write_fslave_makefile(path, syscalls):
    write_makefile(path, pickup_sources(syscalls, "fslave_"))

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

def write_c_footer(p):
    p("""\
/**
 * vim: filetype=c
 */
""")

def write_dispatch(dirpath, syscalls):
    with open(join(dirpath, "dispatch.inc"), "w") as fp:
        p, _ = partial_print(fp)
        for syscall in syscalls:
            if syscall.name not in SYSCALLS:
                continue
            cmd = make_cmd_name(syscall.name)
            name = drop_prefix(syscall.name)
            p("""\
\t\tcase CALL_{cmd}:
\t\t\tprocess_{name}(slave);
\t\t\tbreak;
""".format(**locals()))
        write_c_footer(p)

def write_cases(path, syscalls, prefix):
    with open(path, "w") as fp:
        p, _ = partial_print(fp)
        for syscall in syscalls:
            if syscall.name not in SYSCALLS:
                continue
            cmd = make_cmd_name(syscall.name)
            p("""\
\tcase {prefix}{cmd}:
""".format(**locals()))
        write_c_footer(p)

def write_fshub_dispatch(dirpath, syscalls):
    write_cases(join(dirpath, "dispatch_call.inc"), syscalls, "CALL_")
    write_cases(join(dirpath, "dispatch_ret.inc"), syscalls, "RET_")

write_fmhub_dispatch = write_fshub_dispatch

def write_pre_post_h(dirpath, syscalls):
    with open(join(dirpath, "fmaster_pre_post.h"), "w") as fp:
        p = fp.write
        print_newline = partial(p, "\n")

        print_caution(p)
        p("""\
#include <sys/proc.h>

#include <sys/fmaster/fmaster_proto.h>
""")
        print_newline()

        protos = []
        for syscall in [syscall for syscall in syscalls if syscall.pre_execute]:
            fmt = "int {name}_pre_execute(struct thread *, struct {name}_args *, int *);\n"
            protos.append(fmt.format(name=syscall.name))
        for syscall in [syscall for syscall in syscalls if syscall.post_execute]:
            fmt = "int {name}_post_execute(struct thread *, struct {name}_args *);\n"
            protos.append(fmt.format(name=syscall.name))
        p("".join(sorted(protos)))

def main(dirpath):
    fmaster_root = join(dirpath, "fmaster")
    fmaster_dir = join(fmaster_root, "sys", "fmaster")
    syscalls = read_syscalls(fmaster_dir)
    write_fmaster(fmaster_dir, syscalls)
    write_pre_post_h(fmaster_dir, syscalls)
    MAKEFILE = "Makefile.makesyscalls"
    write_fmaster_makefile(join(fmaster_root, MAKEFILE), syscalls)

    private_dir = join(dirpath, "include", "fsyscall", "private")
    command_dir = join(private_dir, "command")
    write_command(command_dir, syscalls)

    fslave_dir = join(dirpath, "fslave")
    write_fslave(fslave_dir, syscalls)
    write_dispatch(fslave_dir, syscalls)

    write_fshub_dispatch(join(dirpath, "fshub"), syscalls)
    write_fmhub_dispatch(join(dirpath, "fmhub"), syscalls)

    write_fslave_makefile(join(fslave_dir, MAKEFILE), syscalls)
    write_proto(join(private_dir, "fslave"), syscalls)

def usage():
    print("usage: {prog} dirpath".format(prog=basename(argv[0])))

if __name__ == "__main__":
    main(abspath(getcwd()) if len(argv) != 2 else argv[1])

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
