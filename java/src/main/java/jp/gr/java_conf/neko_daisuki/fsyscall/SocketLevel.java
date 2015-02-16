package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.HashMap;
import java.util.Map;

public class SocketLevel {

    public static final SocketLevel SOL_SOCKET = new SocketLevel(
            "SOL_SOCKET",
            0xffff);

    private static final Map<Integer, SocketLevel> mLevels;

    private String mName;
    private int mValue;

    private SocketLevel(String name, int value) {
        mName = name;
        mValue = value;
    }

    @Override
    public boolean equals(Object o) {
        SocketLevel l;
        try {
            l = (SocketLevel)o;
        }
        catch (ClassCastException unused) {
            return false;
        }
        return mValue == l.mValue;
    }

    @Override
    public int hashCode() {
        return Integer.valueOf(mValue).hashCode();
    }

    public String toString() {
        return mName;
    }

    public static SocketLevel valueOf(int level) {
        return mLevels.get(Integer.valueOf(level));
    }

    public static String toString(int level) {
        SocketLevel sol = valueOf(level);
        return sol != null ? sol.toString() : "unknown socket level";
    }

    static {
        mLevels = new HashMap<Integer, SocketLevel>();

        SocketLevel[] levels = { SOL_SOCKET };
        int len = levels.length;
        for (int i = 0; i < len; i++) {
            SocketLevel level = levels[i];
            mLevels.put(Integer.valueOf(level.mValue), level);
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
