
from functools import partial
from os.path import join

from fsyscall.share import FMASTER_SYSCALLS, SYSCALLS, Variable,        \
                           bufsize_of_datatype,                         \
                           concrete_datatype_of_abstract_datatype,      \
                           data_of_argument, drop_prefix,               \
                           input_arguments_of_syscall, make_cmd_name,   \
                           make_payload_size_expr, opt_of_syscall,      \
                           out_arguemnts_of_syscall, partial_print,     \
                           pickup_sources, print_caution, print_locals, \
                           write_makefile

def make_string_locals(name):
    a = []
    for datatype, fmt, size in (
            ("char *", "{name}", None),
            ("size_t", "{name}_len", None),
            ("char", "{name}_len_buf", "FSYSCALL_BUFSIZE_UINT64"),
            ("int", "{name}_len_len", None)):
        a.append(Variable(datatype, fmt.format(**locals()), size))
    return a

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

def print_fmaster_write(p, buf, size, indent=1):
    tabs = indent * "\t"
    p("""\
{tabs}error = fmaster_write(td, wfd, {buf}, {size});
{tabs}if (error != 0)
{tabs}\treturn (error);
""".format(**locals()))

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

def make_basic_local_vars(syscall):
    return [Variable("int", "error")] + (
            [Variable("int", "type_of_fd")]
            if "fd" in [a.name for a in syscall.args]
            else [])

def print_master_call(p, print_newline, syscall):
    if "fd" not in [a.name for a in syscall.args]:
        return
    name = drop_prefix(syscall.name)
    p("""\
\ttype_of_fd = fmaster_type_of_fd(td, uap->fd);
\tif (type_of_fd == FD_CLOSED) {{
\t\treturn (EBADF);
\t}}
\tif (type_of_fd == FD_MASTER) {{
\t\tstruct {name}_args a;
\t\tstruct fmaster_fd *fds = fmaster_fds_of_thread(td);
\t\tmemcpy(&a, uap, sizeof(a));
\t\ta.fd = fds[uap->fd].fd_local;
\t\terror = sys_{name}(td, &a);
\t\tif (error != 0)
\t\t\treturn (error);
""".format(**locals()))
    if syscall.post_common:
        p("""\
\t\terror = fmaster_{name}_post_common(td, uap);
\t\tif (error != 0)
\t\t\treturn (error);
""".format(**locals()))
    p("""\
\t\treturn (0);
\t}}
""".format(**locals()))
    print_newline()

def print_generic_tail(p, print_newline, syscall):
    print_call_tail(p, print_newline)

    local_vars = make_basic_local_vars(syscall)
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
    bit_num = 32 if syscall.rettype == "int" else 64
    p("""\
\terror = execute_call(td, uap);
\tif (error != 0)
\t\treturn (error);
\terror = fmaster_execute_return_generic{bit_num}(td, RET_{cmd_name});
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))
    if syscall.post_execute:
        p("""\
\terror = {name}_post_execute(td, uap);
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))
    if syscall.post_common:
        p("""\
\terror = {name}_post_common(td, uap);
\tif (error != 0)
\t\treturn (error);
""".format(**locals()))
    p("""\
\treturn (0);
}}
""".format(**locals()))

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
    local_vars = make_basic_local_vars(syscall)
    name = syscall.name
    p("""\
int
sys_{name}(struct thread *td, struct {name}_args *uap)
{{
""".format(**locals()))
    print_locals(p, local_vars)
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
        for syscall in [syscall for syscall in syscalls if syscall.post_common]:
            fmt = "int {name}_post_common(struct thread *, struct {name}_args *);\n"
            protos.append(fmt.format(name=syscall.name))
        p("".join(sorted(protos)))

def write_fmaster_makefile(path, syscalls):
    srcs = pickup_sources(syscalls, "fmaster_")

    for syscall in [syscall for syscall in syscalls if syscall.pre_execute]:
        name = syscall.name
        srcs.append("{name}_pre_execute.c".format(**locals()))
    for syscall in [syscall for syscall in syscalls if syscall.post_execute]:
        name = syscall.name
        srcs.append("{name}_post_execute.c".format(**locals()))
    for syscall in [syscall for syscall in syscalls if syscall.post_common]:
        name = syscall.name
        srcs.append("{name}_post_common.c".format(**locals()))

    write_makefile(path, srcs)

def write_implementation(dirpath, syscalls):
    for syscall in [sc for sc in syscalls if sc.name in FMASTER_SYSCALLS]:
        write_syscall(dirpath, syscall)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python