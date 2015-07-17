package jp.gr.java_conf.neko_daisuki.fsyscall.util;

public class StringUtil {

    public static String quote(String s) {
        return s != null ? quoteNotNull(s) : "null";
    }

    private static String quoteNotNull(String s) {
        StringBuilder buf = new StringBuilder("\"");
        int len = s.length();
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\"':
                    buf.append("\\\"");
                    break;
                case '\\':
                    buf.append("\\\\");
                    break;
                default:
                    buf.append(c);
                    break;
            }
        }
        buf.append("\"");

        return buf.toString();
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
