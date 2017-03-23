package jp.gr.java_conf.neko_daisuki.fsyscall.util;

public class PhysicalPath extends NormalizedPath {

    public PhysicalPath(PhysicalPath parent, String path) {
        super(parent, path);
    }

    public PhysicalPath(String path) throws InvalidPathException {
        super(path);
    }

    @Override
    public boolean equals(Object o) {
        PhysicalPath path;
        try {
            path = (PhysicalPath)o;
        }
        catch (ClassCastException unused) {
            return false;
        }
        return path.toString().equals(toString());
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
