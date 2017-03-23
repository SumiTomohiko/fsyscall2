package jp.gr.java_conf.neko_daisuki.fsyscall.util;

public class VirtualPath extends NormalizedPath {

    public VirtualPath(VirtualPath parent, String path) {
        super(parent, path);
    }

    public VirtualPath(String path) throws InvalidPathException {
        super(path);
    }

    @Override
    public boolean equals(Object o) {
        VirtualPath path;
        try {
            path = (VirtualPath)o;
        }
        catch (ClassCastException unused) {
            return false;
        }
        return path.toString().equals(toString());
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
