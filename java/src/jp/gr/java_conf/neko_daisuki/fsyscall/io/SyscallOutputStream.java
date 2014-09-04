package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;

public class SyscallOutputStream {

    private OutputStream mOut;

    public SyscallOutputStream(OutputStream stream) {
        mOut = stream;
    }

    public void copyInputStream(SyscallInputStream in, PayloadSize size) throws IOException {
        int rest = size.toInteger();
        while (0 < rest) {
            int nBytes = Math.min(rest, 8192);
            write(in.read(nBytes));
            rest -= nBytes;
        }
    }

    public void write(byte n) throws IOException {
        mOut.write(new byte[] { n });
    }

    public void write(int n) throws IOException {
        write(Encoder.encodeInteger(n));
    }

    public void write(PayloadSize size) throws IOException {
        write(size.toInteger());
    }

    public void write(byte buffer[]) throws IOException {
        mOut.write(buffer);
    }

    public void write(Command command) throws IOException {
        write(command.toInteger());
    }

    public void write(Pid pid) throws IOException {
        write(pid.toInteger());
    }

    public void close() throws IOException {
        mOut.close();
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
