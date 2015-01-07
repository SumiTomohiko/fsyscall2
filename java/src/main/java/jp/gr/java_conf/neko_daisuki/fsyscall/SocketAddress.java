package jp.gr.java_conf.neko_daisuki.fsyscall;

public class SocketAddress {

    private int mLen;
    private int mFamily;

    public SocketAddress(int len, int family) {
        mLen = len;
        mFamily = family;
    }

    public int getFamily() {
        return mFamily;
    }

    public int getLength() {
        return mLen;
    }

    public int length() {
        return 2;
    }

    protected String getBaseString() {
        return String.format("sa_len=%d, sa_family=%d", mLen, mFamily);
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
