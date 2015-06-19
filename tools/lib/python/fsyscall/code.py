
from re import split
from fsyscall.share import partial_print

class Code:

    def __init__(self, name, value):
        self.name = name
        self.value = value

def print_vim_special_comment(p):
    # If this code is at bottom of this file, vim uses the string as a special
    # comment (vim assumes that this is a C code). So I placed this code at
    # middle of the file.
    p("""\
/**
 * vim: filetype=c
 */
""")

def read_codes(filepath):
    a = []
    with open(filepath) as fp:
        for line in fp:
            if line.startswith("/* end command"):
                break
            cols = split(r"\s+", line.rstrip())
            if (len(cols) != 3) or (cols[0] != "#define"):
                continue
            a.append(Code(cols[1], int(cols[2])))
    return a

def write_names(path, codes):
    f = lambda c: c.value
    code_min = min(codes, key=f).value
    code_max = max(codes, key=f).value + 1

    d = {}
    for c in codes:
        d[c.value] = c.name

    with open(path, "w") as fp:
        p, print_newline = partial_print(fp)
        p("""\
#define\tCODE_MIN\t{code_min}
#define\tCODE_MAX\t{code_max}
#define\tCODE_NAMES\t{{ \\
""".format(**locals()))
        for value in range(code_min, code_max):
            try:
                name = d[value]
            except KeyError:
                name = "undefined"
            p("""\
\t\"{name}\", /* {value} */\\
""".format(**locals()))
        p("""\
}}
""".format(**locals()))
        print_vim_special_comment(p)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
