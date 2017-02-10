package jp.gr.java_conf.neko_daisuki.fsyscall.util;

import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;

public class IoVecUtil {

    public static String toString(Unix.IoVec[] iovec, int len) {
        return iovec != null ? chain(iovec, len) : "null";
    }

    private static String chain(Unix.IoVec[] iovec, int len) {
        int n = iovec.length;
        String[] sa = new String[n];
        for (int i = 0; i < n; i++) {
            Unix.IoVec v = iovec[i];
            sa[i] = v != null ? v.toString(len) : null;
        }

        return ArrayUtil.toString(sa);
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
