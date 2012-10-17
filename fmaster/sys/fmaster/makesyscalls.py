#!/usr/local/bin/python3.2

from os.path import basename, dirname, join
from re import search
from sys import argv, exit

class Argument:

    def __init__(self, datatype, name):
        self.datatype = datatype
        self.name = name

    def __str__(self):
        datatype = self.datatype
        space = "" if datatype[-1] == "*" else " "
        name = self.name
        return "{datatype}{space}{name}".format(**locals())

class Syscall:

    def __init__(self):
        self.rettype = None
        self.name = None
        self.args = []

    def __str__(self):
        args = ", ".join([str(a) for a in self.args])
        fmt = "{rettype} {name}({args})"
        return fmt.format(rettype=self.rettype, name=self.name, args=args)

SYSCALLS = {
        "fmaster_read": None
        }

def split_datatype_name(datatype_with_name):
    index = search(r"\w+$", datatype_with_name).start()
    return datatype_with_name[:index].strip(), datatype_with_name[index:]

def parse_proto(proto):
    assert proto[-2:] == ");"
    lpar = proto.index("(")
    rpar = proto.rindex(")")
    rettype, name = split_datatype_name(proto[:lpar])
    args = [a.strip() for a in proto[lpar + 1:rpar].split(",")]

    syscall = Syscall()
    syscall.rettype = rettype
    syscall.name = name
    for a in args:
        datatype, name = split_datatype_name(a)
        syscall.args.append(Argument(datatype, name))

    return syscall

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
        print(syscall)

def usage():
    print("Usage: {prog} dirpath".format(prog=basename(argv[0])))

if __name__ == "__main__":
    main(dirname(__file__) if len(argv) != 2 else argv[1])

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
