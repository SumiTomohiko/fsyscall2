
from os.path import join
from re import search

from fsyscall.java.share import get_package_path
from fsyscall.share import SYSCALLS, apply_template, datasize_of_datatype,  \
                           drop_prefix, opt_of_syscall

class Global:

    def __init__(self):
        self.manually_defined_syscalls = None
        self.pkg_dir = None

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

def write_command_java(g, syscalls):
    path = join(g.pkg_dir, "Command.java")
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
    return ", ".join([a.name for a in syscall.input_args])

def make_params_declarations(syscall):
    stmts = []
    for a in syscall.input_args:
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
    for a in syscall.input_args:
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

def rettype_class_of_syscall(syscall):
    if len(syscall.output_args) == 0:
        fmt = "Generic{size}"
        return fmt.format(size=datasize_of_datatype(syscall.rettype))
    return drop_prefix(syscall.name).capitalize()

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
            SyscallResult.{rettype} result = mSlave.do{name}({args});
            mSlave.writeResult(Command.{cmd}, result);
        }}
    }}"""
        proc = make_proc(syscall)
        decls = make_params_declarations(syscall)
        params = make_params_reading(syscall)
        rettype = rettype_class_of_syscall(syscall)
        name = make_class_prefix(syscall)
        args = make_params_passing(syscall)
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

def get_helper_path(g):
    return join(get_slave_dir(g.pkg_dir), "SlaveHelper.java")

def write_slave(g, syscalls):
    d = {
            "PROCS": build_proc_of_protocol(syscalls),
            "DISPATCHES": build_dispatch_of_protocol(syscalls) }
    apply_template(d, get_helper_path(g))

def build_members_of_result(syscall):
    stmts = []
    for a in syscall.output_args:
        datatype = java_datatype_of_c_datatype(a.datatype)
        name = a.name
        stmts.append("public {datatype} {name}".format(**locals()))
    return ";\n        ".join(stmts)

def build_syscall_results(g, syscalls):
    stmts = []
    for syscall in syscalls:
        if syscall.name in g.manually_defined_syscalls:
            continue
        if len(syscall.output_args) == 0:
            continue
        name = drop_prefix(syscall.name).capitalize()
        size = datasize_of_datatype(syscall.rettype)
        base = "Generic{size}".format(**locals())
        members = build_members_of_result(syscall)

        stmts.append("""public static class {name} extends {base} {{

        {members};
    }}""".format(**locals()))

    return "\n\n    ".join(stmts)

def write_syscall_result(g, syscalls):
    d = { "RESULTS": build_syscall_results(g, syscalls) }
    apply_template(d, join(g.pkg_dir, "SyscallResult.java"))

def find_manually_defined_syscalls(g):
    syscalls = []
    with open(get_helper_path(g) + ".in") as fp:
        for line in fp:
            m = search(r"(?P<name>\w+)Proc", line)
            if m is None:
                continue
            name = m.group("name").lower()
            syscalls.append(name)

    return syscalls

def write(dirpath, syscalls):
    g = Global()
    g.pkg_dir = get_package_path(dirpath)
    g.manually_defined_syscalls = find_manually_defined_syscalls(g)

    write_command_java(g, syscalls)
    write_slave(g, syscalls)
    write_syscall_result(g, syscalls)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
