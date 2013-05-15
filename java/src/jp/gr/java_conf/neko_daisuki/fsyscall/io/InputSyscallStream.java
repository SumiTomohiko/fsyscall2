package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.InputStream;

public class InputSyscallStream {

    private InputStream mStream;

    public InputSyscallStream(InputStream stream) {
        mStream = stream;
    }

    public boolean isReady() throws IOException {
        return 0 < mStream.available();
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
