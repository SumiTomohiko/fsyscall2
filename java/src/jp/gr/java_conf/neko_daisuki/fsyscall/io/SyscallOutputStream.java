package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;

public class SyscallOutputStream {

    private OutputStream mOut;

    public SyscallOutputStream(OutputStream stream) {
        mOut = stream;
    }

    public void copyInputStream(SyscallInputStream in, int size) throws IOException {
        int rest = size;
        while (0 < rest) {
            int nBytes = Math.min(rest, 8192);
            write(in.read(nBytes));
            rest -= nBytes;
        }
    }

    public void writeByte(byte n) throws IOException {
        mOut.write(new byte[] { n });
    }

    public void writeInteger(int n) throws IOException {
        write(Encoder.encodeInteger(n));
    }

    public void writePayloadSize(int n) throws IOException {
        writeInteger(n);
    }

    public void write(byte buffer[]) throws IOException {
        mOut.write(buffer);
    }

    public void writeCommand(Command command) throws IOException {
        writeInteger(command.toInteger());
    }

    public void writePid(Pid pid) throws IOException {
        writeInteger(pid.getInteger());
    }

    public void close() throws IOException {
        mOut.close();
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
