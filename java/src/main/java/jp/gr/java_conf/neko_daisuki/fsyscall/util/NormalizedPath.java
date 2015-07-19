package jp.gr.java_conf.neko_daisuki.fsyscall.util;

import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

public class NormalizedPath {

    public static class InvalidPathException extends Exception {

        public InvalidPathException(String message, String path) {
            super(String.format("%s: %s", message, path));
        }
    }

    private static final String SEPARATOR = "/";

    private String mPath;

    public NormalizedPath(NormalizedPath parent, String path) {
        if (path == null) {
            throw new NullPointerException("null given as path");
        }
        boolean isAbsolute = path.startsWith(SEPARATOR);
        String s = isAbsolute ? path : String.format("%s%s%s",
                                                     parent.toString(),
                                                     SEPARATOR,
                                                     path);
        mPath = normalize(s);
    }

    public NormalizedPath(String path) throws InvalidPathException {
        if (path == null) {
            throw new NullPointerException("null given as path");
        }
        if (path.startsWith(SEPARATOR)) {
            throw new InvalidPathException("path must be absolute", path);
        }
        mPath = normalize(path);
    }

    @Override
    public boolean equals(Object o) {
        NormalizedPath path;
        try {
            path = (NormalizedPath) o;
        }
        catch (ClassCastException unused) {
            return false;
        }
        return path.toString().equals(mPath);
    }

    @Override
    public int hashCode() {
        return mPath.hashCode();
    }

    @Override
    public String toString() {
        return mPath;
    }

    private String chainElements(List<String> l) {
        StringBuilder buf = new StringBuilder();
        int size = l.size();
        for (int i = 0; i < size; i++) {
            buf.append(SEPARATOR);
            buf.append(l.get(i));
        }
        return buf.toString();
    }

    private String normalize(String path) {
        String[] sa = path.split(SEPARATOR);
        LinkedList<String> l = new LinkedList<String>();
        int len = sa.length;
        for (int i = 1; i < len; i++) {
            String name = sa[i];
            if (name.equals(".")) {
            }
            else if (name.equals("..")) {
                try {
                    l.removeLast();
                }
                catch (NoSuchElementException unused) {
                    // stay at the root directory.
                }
            }
            else {
                l.addLast(name);
            }
        }

        return l.size() == 0 ? SEPARATOR : chainElements(l);
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
