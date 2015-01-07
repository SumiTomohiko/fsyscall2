package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.InputStream;
import java.io.OutputStream;

class Pair {

    private InputStream mIn;
    private OutputStream mOut;

    public Pair(InputStream in, OutputStream out) {
        mIn = in;
        mOut = out;
    }

    public InputStream getInputStream() {
        return mIn;
    }

    public OutputStream getOutputStream() {
        return mOut;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
