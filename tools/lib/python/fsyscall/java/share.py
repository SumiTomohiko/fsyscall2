
from os.path import join

def get_package_path(dirpath):
    names = ["src", "jp", "gr", "java_conf", "neko_daisuki", "fsyscall"]
    return join(dirpath, *names)

# vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python
