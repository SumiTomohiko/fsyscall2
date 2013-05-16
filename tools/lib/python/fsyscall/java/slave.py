
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
    package_path = get_package_path(dirpath)
    path = join(package_path, "Command.java")
    d = {
            "ENUM_COMMAND": make_enum_command(syscalls),
            "NUMBER2COMMAND": make_number2command(syscalls),
            "COMMAND2NUMBER": make_command2number(syscalls) }
    apply_template(path, d)

def write(dirpath, syscalls):
    write_command_java(dirpath, syscalls)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
