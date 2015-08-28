
from functools import partial
from re import compile, search, sub
from sys import argv

LINE_WIDTH = 80
RE_ARRAY_DATATYPE = compile(r"^(?P<type>.+) \(\*\)\[(?P<size>.+)\]$")

class Struct:

    def __init__(self, name, members):
        self.name = name
        self.members = members

    def _list_all_members(self, prefix, sep, first_sep=None):
        if first_sep is None:
            return self._list_all_members(prefix, sep, sep)

        a = []
        for member in self.members:
            s = first_sep.join([prefix, member.name])
            datatype = member.datatype
            if isinstance(datatype, Struct):
                a.extend(datatype._list_all_members(s, sep, sep))
                continue
            a.append((datatype, s))
        return a

    def expand_all_members(self, prefix):
        return self._list_all_members(prefix, "_")

    def list_all_members(self, prefix, first_sep):
        return self._list_all_members(prefix, ".", first_sep)

    def zip_members(self, prefix, first_sep=None):
        a = self.expand_all_members(prefix)
        b = self.list_all_members(prefix, first_sep)
        c = []
        for p, q in zip(a, b):
            c.append((p[0], p[1], q[1]))
        return c

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

stat = Struct("stat", [
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

timeval = Struct("timeval", [
    Variable("time_t", "tv_sec"),
    Variable("suseconds_t", "tv_usec")
    ])

timezone = Struct("timezone", [
    Variable("int", "tz_minuteswest"),
    Variable("int", "tz_dsttime")
    ])

rusage = Struct("rusage", [
    Variable(timeval, "ru_utime"),
    Variable(timeval, "ru_stime"),
    Variable("long", "ru_maxrss"),
    Variable("long", "ru_ixrss"),
    Variable("long", "ru_idrss"),
    Variable("long", "ru_isrss"),
    Variable("long", "ru_minflt"),
    Variable("long", "ru_majflt"),
    Variable("long", "ru_nswap"),
    Variable("long", "ru_inblock"),
    Variable("long", "ru_oublock"),
    Variable("long", "ru_msgsnd"),
    Variable("long", "ru_msgrcv"),
    Variable("long", "ru_nsignals"),
    Variable("long", "ru_nvcsw"),
    Variable("long", "ru_nivcsw")
    ])

class Argument:

    def __init__(self, opt=None, out=False, size=None, retsize=None, struct=None, fd=False):
        self.opt = opt
        self.out = out
        self.size = size
        self.retsize = retsize
        self.struct = struct
        self.fd = fd

    def get_is_atom(self):
        return (self.struct is None) and (self.size is None)

    is_atom = property(get_is_atom)

    def get_is_array(self):
        return self.size is not None

    is_array = property(get_is_array)

GETRESXID_ARGS = {
        "ruid": Argument(out=True),
        "euid": Argument(out=True),
        "suid": Argument(out=True)
        }

SYSCALLS = {
        "fmaster_read": {
            "fd": Argument(fd=True),
            "buf": Argument(out=True, size="nbytes", retsize="retval")
            },
        "fmaster_write": {
            "fd": Argument(fd=True),
            "buf": Argument(size="nbytes")
            },
        "fmaster_open": {
            "mode": Argument(opt="(flags & O_CREAT) != 0")
            },
        "fmaster_link": {},
        "fmaster_access": {},
        "fmaster_fstat": {
            "fd": Argument(fd=True),
            "sb": Argument(out=True, struct=stat)
            },
        "fmaster_lstat": {
            "ub": Argument(out=True, struct=stat)
            },
        "fmaster_stat": {
            "ub": Argument(out=True, struct=stat)
            },
        "fmaster_issetugid": {},
        "fmaster_lseek": {
            "fd": Argument(fd=True)
            },
        "fmaster_pread": {
            "fd": Argument(fd=True),
            "buf": Argument(out=True, size="nbyte", retsize="retval")
            },
        "fmaster_readlink": {
            "buf": Argument(out=True, size="count", retsize="retval")
            },
        "fmaster_writev": {
            "fd": Argument(fd=True),
            "iovp": Argument(size="iovcnt")
            },
        "fmaster_fcntl": {
            "fd": Argument(fd=True)
            },
        "fmaster_getpid": {},
        "fmaster_getuid": {},
        "fmaster_geteuid": {},
        "fmaster_getgid": {},
        "fmaster_getegid": {},
        "fmaster_socket": {},
        "fmaster_gettimeofday": {
            "tp": Argument(opt="tp != NULL", out=True, struct=timeval),
            "tzp": Argument(opt="tzp != NULL", out=True, struct=timezone)
            },
        "fmaster_getresuid": {
            "ruid": Argument(out=True),
            "euid": Argument(out=True),
            "suid": Argument(out=True)
            },
        "fmaster_getresgid": {
            "rgid": Argument(out=True),
            "egid": Argument(out=True),
            "sgid": Argument(out=True)
            },
        "fmaster_wait4": {
            "status": Argument(out=True),
            "rusage": Argument(out=True, struct=rusage)
            },
        "fmaster_listen": {
            "s": Argument(fd=True)
            },
        "fmaster_kill": {},
        "fmaster_chdir": {},
        "fmaster_chmod": {},
        "fmaster_mkdir": {},
        "fmaster_unlink": {},
        "fmaster_rmdir": {}
        }

FMASTER_SYSCALLS = SYSCALLS
FSLAVE_SYSCALLS = SYSCALLS
DUMMY_SYSCALLS = [
        "fmaster_fchdir", "fmaster_mknod", "fmaster_chown", "fmaster_mount",
        "fmaster_unmount", "fmaster_setuid", "fmaster_ptrace",
        "fmaster_recvmsg", "fmaster_chflags", "fmaster_fchflags",
        "fmaster_sync", "fmaster_getppid", "fmaster_profil", "fmaster_ktrace",
        "fmaster_getlogin", "fmaster_setlogin", "fmaster_acct",
        "fmaster_reboot", "fmaster_revoke", "fmaster_symlink", "fmaster_umask",
        "fmaster_chroot", "fmaster_msync", "fmaster_vfork", "fmaster_ovadvise",
        "fmaster_getgroups", "fmaster_setgroups", "fmaster_getpgrp",
        "fmaster_setpgid", "fmaster_setitimer", "fmaster_getitimer",
        "fmaster_fsync", "fmaster_setpriority", "fmaster_getpriority",
        "fmaster_getrusage", "fmaster_readv", "fmaster_settimeofday",
        "fmaster_fchown", "fmaster_fchmod", "fmaster_setreuid",
        "fmaster_setregid", "fmaster_rename", "fmaster_flock", "fmaster_mkfifo",
        "fmaster_shutdown", "fmaster_utimes", "fmaster_adjtime",
        "fmaster_quotactl", "fmaster_nlm_syscall", "fmaster_nfssvc",
        "fmaster_lgetfh", "fmaster_getfh", "fmaster_rtprio", "fmaster_semsys",
        "fmaster_msgsys", "fmaster_shmsys", "fmaster_setfib",
        "fmaster_ntp_adjtime", "fmaster_setgid", "fmaster_setegid",
        "fmaster_seteuid", "fmaster_pathconf", "fmaster_fpathconf",
        "fmaster_setrlimit", "fmaster_undelete", "fmaster_futimes",
        "fmaster_getpgid", "fmaster_clock_settime", "fmaster_clock_getres",
        "fmaster_ktimer_create", "fmaster_ktimer_delete",
        "fmaster_ktimer_settime", "fmaster_ktimer_gettime",
        "fmaster_ktimer_getoverrun", "fmaster_rfork", "fmaster_lchown",
        "fmaster_aio_read", "fmaster_aio_write", "fmaster_lio_listio",
        "fmaster_getdents", "fmaster_lchmod", "fmaster_lutimes",
        "fmaster_nstat", "fmaster_nfstat", "fmaster_nlstat", "fmaster_preadv",
        "fmaster_pwritev", "fmaster_fhopen", "fmaster_fhstat", "fmaster_getsid",
        "fmaster_setresuid", "fmaster_setresgid", "fmaster_lchflags",
        "fmaster_sendfile", "fmaster_fhstatfs", "fmaster_setcontext",
        "fmaster_swapcontext", "fmaster_thr_create", "fmaster_thr_exit",
        "fmaster_thr_suspend", "fmaster_thr_wake", "fmaster_thr_new",
        "fmaster_abort2", "fmaster_thr_set_name", "fmaster_pwrite",
        "fmaster_truncate", "fmaster_ftruncate", "fmaster_thr_kill2",
        "fmaster_faccessat", "fmaster_fchmodat", "fmaster_fchownat",
        "fmaster_fexecve", "fmaster_fstatat", "fmaster_futimesat",
        "fmaster_linkat", "fmaster_mkdirat", "fmaster_mkfifoat",
        "fmaster_mknodat", "fmaster_openat", "fmaster_readlinkat",
        "fmaster_renameat", "fmaster_symlinkat", "fmaster_unlinkat",
        "fmaster_posix_openpt", "fmaster_msgctl", "fmaster_lpathconf",
        "fmaster_getloginclass", "fmaster_setloginclass"
        ]

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
            "long": "int64",
            "int": "int32",
            "time_t": "int64",
            "suseconds_t": "int64" }[datatype]

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
    t = datatype.split()[0]
    if t == "struct":
        return 64
    if t == "enum":
        return 32
    DATASIZE_OF_DATATYPE = {
            "sigset_t": 32 * 4,
            "caddr_t": 64,
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
            "long": 64,
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
            "void": 64,
            "pid_t": 32,
            "time_t": 64,
            "suseconds_t": 64 }
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
            for _, name in st.expand_all_members(a.name):
                terms.append("{name}_len".format(**locals()))
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
