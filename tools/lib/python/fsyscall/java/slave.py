
from os.path import join

from fsyscall.java.share import get_package_path
from fsyscall.share import apply_template, drop_prefix

def make_indent(width):
    return " " * width

def make_enum_command(syscalls):
    commands = []
    indent = make_indent(4)
    for syscall in syscalls:
        commands.append(syscall.call_name)
        commands.append(syscall.ret_name)
    return ",\n    ".join(commands)

def make_number2command(syscalls):
    lines = []
    for syscall in syscalls:
        d = vars(syscall)
        d.update({
                "call_name": syscall.call_name,
                "ret_name": syscall.ret_name })
        lines.append("mNumber2Command.put(Integer.valueOf({call_id}), {call_name})".format(**d))
        lines.append("mNumber2Command.put(Integer.valueOf({ret_id}), {ret_name})".format(**d))
    return (";\n" + make_indent(8)).join(lines)

def make_command2number(syscalls):
    lines = []
    for syscall in syscalls:
        d = vars(syscall)
        d.update({
                "call_name": syscall.call_name,
                "ret_name": syscall.ret_name })
        lines.append("mCommand2Number.put({call_name}, Integer.valueOf({call_id}))".format(**d))
        lines.append("mCommand2Number.put({ret_name}, Integer.valueOf({ret_id}))".format(**d))
    return (";\n" + make_indent(8)).join(lines)

def write_command_java(dirpath, syscalls):
    path = join(dirpath, "Command.java")
    d = {
            "ENUM_COMMAND": make_enum_command(syscalls),
            "NUMBER2COMMAND": make_number2command(syscalls),
            "COMMAND2NUMBER": make_command2number(syscalls) }
    apply_template(d, path)

JAVA_DATATYPE_OF_C_DATATYPE = {
        "char *": "String",
        "int": "int",
        "void *": "char[]",
        "size_t": "long",
        # FIXME: u_long must be unsigned long. But Java does not have it.
        "u_long": "long",
        "caddr_t": "char[]",
        "fd_set *": "FdSet",
        "struct timeval *": "TimeVal",
        "struct iovec *": "char[]",
        "u_int": "long",
        "struct stat *": "Stat",
        "off_t": "long"
        }

def java_datatype_of_c_datatype(datatype):
    return JAVA_DATATYPE_OF_C_DATATYPE[datatype]

def make_args_class(syscall):
    return drop_prefix(syscall.name).title() + "Args"

def write_syscall_args(dirpath, syscalls):
    tmpl = join(dirpath, "SyscallArgs.java.in")
    for syscall in syscalls:
        name = make_args_class(syscall)
        members = []
        for a in syscall.args:
            datatype = java_datatype_of_c_datatype(a.datatype)
            s = a.name
            members.append("public {datatype} {s}".format(**locals()))
        d = { "NAME": name, "MEMBERS": ";\n    ".join(members) }
        apply_template(d, join(dirpath, "{name}.java".format(**locals())), tmpl)

def write_protocol(dirpath, syscalls):
    imports = []
    for syscall in syscalls:
        fmt = "import jp.gr.java_conf.neko_daisuki.fsyscall.{clazz}"
        clazz = make_args_class(syscall)
        imports.append(fmt.format(**locals()))

    d = {
            "IMPORTS": ";\n".join(sorted(imports)),
            "CLASSES": "",
            "DISPATCHES": "" }
    apply_template(d, join(dirpath, "slave", "SlaveProtocol.java"))

def write(dirpath, syscalls):
    pkg_dir = get_package_path(dirpath)
    write_command_java(pkg_dir, syscalls)
    write_syscall_args(pkg_dir, syscalls)
    write_protocol(pkg_dir, syscalls)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
