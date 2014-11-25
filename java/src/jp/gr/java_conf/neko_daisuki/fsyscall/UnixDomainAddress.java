package jp.gr.java_conf.neko_daisuki.fsyscall;

public class UnixDomainAddress extends SocketAddress {

    private String mPath;

    public UnixDomainAddress(int len, int family, String path) {
        super(len, family);
        mPath = path;
    }

    public String getPath() {
        return mPath;
    }

    @Override
    public int length() {
        return super.length() + mPath.length();
    }

    public String toString() {
        String fmt = "UnixDomainAddress(%s, sun_path=%s)";
        return String.format(fmt, getBaseString(), mPath);
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
