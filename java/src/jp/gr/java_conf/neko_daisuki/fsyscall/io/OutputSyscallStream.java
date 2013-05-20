package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.OutputStream;

public class OutputSyscallStream {

    private OutputStream mStream;

    public OutputSyscallStream(OutputStream stream) {
        mStream = stream;
    }

    public void writeByte(byte n) throws IOException {
        mStream.write(new byte[] { n });
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
