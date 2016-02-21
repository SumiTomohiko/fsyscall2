package jp.gr.java_conf.neko_daisuki.fsyscall.util;

public class ArrayUtil {

    public static String toString(Object[] a) {
        return a != null ? chain(a) : "null";
    }

    private static String chain(Object[] a) {
        StringBuilder buf = new StringBuilder("[");
        int len = a.length;
        String sep = "";
        for (int i = 0; i < len; i++) {
            buf.append(sep);
            Object o = a[i];
            buf.append(o != null ? o.toString() : "null");
            sep = ", ";
        }
        buf.append("]");
        return buf.toString();
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
