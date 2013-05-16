
from os import mkdir
from os.path import join

from fsyscall.share import FMASTER_SYSCALLS, FSLAVE_SYSCALLS, SYSCALLS, \
                           Variable, bufsize_of_datatype,               \
                           data_of_argument,                            \
                           concrete_datatype_of_abstract_datatype,      \
                           drop_pointer, drop_prefix,                   \
                           input_arguments_of_syscall, make_cmd_name,   \
                           make_decl, make_payload_size_expr,           \
                           opt_of_syscall, out_arguemnts_of_syscall,    \
                           partial_print, pickup_sources,               \
                           print_caution, print_locals, write_c_footer, \
                           write_makefile

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

def get_fslave_return_func(syscall):
    return "return_int" if syscall.rettype == "int" else "return_ssize"

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

def make_execute_return_actual_arguments(syscall, args):
    exprs = []
    for a in args:
        st = data_of_argument(syscall, a).struct
        fmt = "&{name}" if st is not None else "{name}"
        exprs.append(fmt.format(**vars(a)))
    return ", ".join(exprs)

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

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python