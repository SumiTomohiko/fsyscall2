package jp.gr.java_conf.neko_daisuki.fsyscall.util;

public class ByteUtil {

    private static class ChainParam {

        public int length;
        public String postfix;

        public ChainParam(int length, String postfix) {
            this.length = length;
            this.postfix = postfix;
        }
    }

    private static final boolean[] IS_PRINT = {
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false
    };

    private static final String[] CHARS = {
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", "!", "\"", "#", "$", "%", "&", "'",
        "(", ")", "*", "+", ",", "-", ".", "/",
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", ":", ";", "<", "=", ">", "?",
        "@", "A", "B", "C", "D", "E", "F", "G",
        "H", "I", "J", "K", "L", "M", "N", "O",
        "P", "Q", "R", "S", "T", "U", "V", "W",
        "X", "Y", "Z", "[", "\\", "]", "^", "_",
        "`", "a", "b", "c", "d", "e", "f", "g",
        "h", "i", "j", "k", "l", "m", "n", "o",
        "p", "q", "r", "s", "t", "u", "v", "w",
        "x", "y", "z", "{", "|", "}", "~", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " ",
        " ", " ", " ", " ", " ", " ", " ", " "
    };

    /**
     * @param len If -1 is given, this method works for whole of the buffer.
     */
    public static String toString(byte[] buf, int pos, int len) {
        return buf != null ? buildArrayString(buf, pos, len) : "null";
    }

    public static String toString(byte[] buf, int len) {
        return toString(buf, 0, len);
    }

    public static String toString(byte[] buf) {
        return toString(buf, buf.length);
    }

    public static String toString(byte c) {
        if (isPrint(c)) {
            return escape(CHARS[toUnsigned(c)]);
        }

        switch ((char)c) {
        case '\0':
            return "\\0";
        case '\t':
            return "\\t";
        case '\n':
            return "\\n";
        case '\r':
            return "\\r";
        default:
            break;
        }

        return String.format("\\x%02x", c);
    }

    private static int toUnsigned(byte b) {
        return b < 0 ? b - Byte.MIN_VALUE : b;
    }

    private static String buildArrayString(byte[] buf, int pos, int len) {
        ChainParam param = (len != -1) && (len < buf.length)
                ? new ChainParam(len, "...")
                : new ChainParam(buf.length, "");

        StringBuilder builder = new StringBuilder();
        int n = param.length;
        for (int i = 0; i < n; i++) {
            builder.append(toString(buf[pos + i]));
        }
        builder.append(param.postfix);
        return builder.toString();
    }

    private static String escape(String s) {
        return "\\".equals(s) ? "\\\\" : s;
    }

    private static boolean isPrint(byte c) {
        return IS_PRINT[toUnsigned(c)];
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
