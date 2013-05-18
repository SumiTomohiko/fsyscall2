
from functools import partial
from re import compile, search, sub
from sys import argv

LINE_WIDTH = 80
RE_ARRAY_DATATYPE = compile(r"^(?P<type>.+) \(\*\)\[(?P<size>.+)\]$")

class Struct:

    def __init__(self, members):
        self.members = members

def drop_pointer(datatype):
    return datatype if datatype[-1] != "*" else datatype[:-2]

def make_local_decl(local_var):
    ast = "*" if local_var.datatype[-1] == "*" else ""
    name = local_var.name
    make_bracket = lambda: "[{size}]".format(**vars(local_var))
    size = make_bracket() if local_var.size is not None else ""
    return "{ast}{name}{size}".format(**locals())

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

DEFAULT_ARGUMENT = Argument()

def data_of_argument(syscall, a):
    try:
        return SYSCALLS[syscall.name][a.name]
    except KeyError:
        return DEFAULT_ARGUMENT

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

def bufsize_of_datatype(datatype):
    concrete = concrete_datatype_of_abstract_datatype(datatype)
    return "FSYSCALL_BUFSIZE_" + concrete.upper()

def partial_print(fp):
    p = partial(print, end="", file=fp)
    return p, partial(p, "\n")

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

def strlen(s):
    return len(s.replace("\t", 8 * " "))

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

def locals_of_datatype(local_vars, datatype):
    return [v for v in local_vars if drop_pointer(v.datatype) == datatype]

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

def opt_of_syscall(tab, syscall, a):
    try:
        return tab[syscall.name][a.name].opt
    except KeyError:
        return None

def make_cmd_name(name):
    prefix = "fmaster_"
    assert name[:len(prefix)] == prefix
    return name[len(prefix):].upper()

def input_arguments_of_syscall(syscall):
    return [a for a in syscall.args if not data_of_argument(syscall, a).out]

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

def pickup_sources(syscalls, prefix):
    srcs = []

    a = [syscall for syscall in syscalls if syscall.name in FSLAVE_SYSCALLS]
    for syscall in a:
        name = drop_prefix(syscall.name)
        srcs.append("{prefix}{name}.c".format(**locals()))

    return srcs

def drop_prefix(s):
    return s[s.find("_") + 1:]

def write_c_footer(p):
    p("""\
/**
 * vim: filetype=c
 */
""")

def out_arguemnts_of_syscall(syscall):
    return [a for a in syscall.args if data_of_argument(syscall, a).out]

RE_VAR = compile(r"@(?P<name>[A-Za-z_]\w*)@")

def apply_template(d, path, tmpl=None):
    if tmpl is None:
        return apply_template(d, path, path + ".in")

    with open(path, "w") as fpout:
        p = partial(print, end="", file=fpout)
        print_caution(p)

        with open(tmpl, "r") as fpin:
            for line in fpin:
                p(sub(RE_VAR, lambda m: d[m.group("name")], line))

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
