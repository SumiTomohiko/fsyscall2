package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;

public class SyscallOutputStream {

    private OutputStream mStream;

    public SyscallOutputStream(OutputStream stream) {
        mStream = stream;
    }

    public void writeByte(byte n) throws IOException {
        mStream.write(new byte[] { n });
    }

    public void writeInteger(int n) throws IOException {
        write(Encoder.encodeInteger(n));
    }

    public void write(byte buffer[]) throws IOException {
        mStream.write(buffer);
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
