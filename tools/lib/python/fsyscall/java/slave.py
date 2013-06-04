
from os.path import join

from fsyscall.java.share import get_package_path
from fsyscall.share import SYSCALLS, apply_template, drop_prefix, opt_of_syscall

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

def make_class_prefix(syscall):
    return drop_prefix(syscall.name).title()

def make_proc(syscall):
    return make_class_prefix(syscall) + "Proc"

def make_params_passing(syscall):
    return ", ".join([a.name for a in syscall.args])

def make_params_declarations(syscall):
    stmts = []
    for a in syscall.args:
        opt = opt_of_syscall(SYSCALLS, syscall, a)

        name = a.name
        datatype = java_datatype_of_c_datatype(a.datatype)
        initval = "" if opt is None else " = 0"
        stmts.append("{datatype} {name}{initval}".format(**locals()))

    return (";\n" + 12 * " ").join(stmts)

READ_METHOD_OF_C_DATATYPE = {
        "int": "readInteger",
        "char *": "readString" }

def read_method_of_c_datatype(datatype):
    return READ_METHOD_OF_C_DATATYPE.get(datatype)

def make_params_reading(syscall):
    stmts = []
    for a in syscall.args:
        opt = opt_of_syscall(SYSCALLS, syscall, a)
        indent = (0 if opt is None else 4) * " "

        name = a.name
        datatype = java_datatype_of_c_datatype(a.datatype)
        meth = read_method_of_c_datatype(a.datatype)
        if meth is None:
            # TODO: Remove here. This is temporary escaping from compile error.
            if (a.datatype[len(a.datatype) - 1] == "*") or (a.datatype == "caddr_t"):
                initval = "null"
            else:
                initval = "0"
            stmts.append("{indent}{name} = {initval};".format(**locals()))
            continue

        if opt is not None:
            stmts.append("if ({opt}) {{".format(**locals()))
        stmts.append("{indent}{name} = mIn.{meth}();".format(**locals()))
        if opt is not None:
            stmts.append("}")

    return ("\n" + 12 * " ").join(stmts)

def build_proc_of_protocol(syscalls):
    procs = []
    for syscall in syscalls:
        if syscall.name == "fmaster_exit":
            continue

        fmt = """private class {proc} extends CommandDispatcher.Proc {{

        public void call(Command command) throws IOException {{
            PayloadSize payloadSize = mIn.readPayloadSize();
            {decls};
            {params}
            SyscallResult result = mSlave.do{name}({args});
            mSlave.writeResultGeneric{postfix}(Command.{cmd}, result);
        }}
    }}"""
        proc = make_proc(syscall)
        decls = make_params_declarations(syscall)
        params = make_params_reading(syscall)
        name = make_class_prefix(syscall)
        args = make_params_passing(syscall)
        postfix = 64 if syscall.rettype == "off_t" else 32
        cmd = syscall.ret_name
        procs.append(fmt.format(**locals()))

    return ("\n\n" + make_indent(4)).join(procs)

def build_dispatch_of_protocol(syscalls):
    dispatches = []
    for syscall in syscalls:
        fmt = "dispatcher.addEntry(Command.{cmd}, new {proc}())"
        cmd = syscall.call_name
        proc = make_proc(syscall)
        dispatches.append(fmt.format(**locals()))
    return (";\n" + make_indent(8)).join(dispatches)

def get_slave_dir(dirpath):
    return join(dirpath, "slave")

def write_slave(dirpath, syscalls):
    d = {
            "PROCS": build_proc_of_protocol(syscalls),
            "DISPATCHES": build_dispatch_of_protocol(syscalls) }
    apply_template(d, join(get_slave_dir(dirpath), "SlaveHelper.java"))

def write(dirpath, syscalls):
    pkg_dir = get_package_path(dirpath)
    write_command_java(pkg_dir, syscalls)
    write_slave(pkg_dir, syscalls)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
