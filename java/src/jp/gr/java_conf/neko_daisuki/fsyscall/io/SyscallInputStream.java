package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.InputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;

public class SyscallInputStream {

    private enum Status {
        OPEN,
        CLOSED };

    private static Logging.Logger mLogger;

    private Status mStatus;
    private InputStream mIn;

    public SyscallInputStream(InputStream in) {
        mStatus = Status.OPEN;
        mIn = in;
    }

    public boolean isReady() throws IOException {
        return (mStatus == Status.OPEN) && (0 < mIn.available());
    }

    public Command readCommand() throws IOException {
        int n = readInteger();
        String fmt = "numeric representation of the command is %d.";
        mLogger.info(String.format(fmt, n));

        Command command = Command.fromInteger(n);
        mLogger.info(String.format("command is %s.", command));

        return Command.fromInteger(n);
    }

    public void close() throws IOException {
        mStatus = Status.CLOSED;
        mIn.close();
    }

    /**
     * Reads signed int (32bits). This method cannot handle unsigned int.
     */
    public int readInteger() throws IOException {
        int n = 0;
        int shift = 0;
        int m;
        while (((m = mIn.read()) & 0x80) != 0) {
            n += ((m & 0x7f) << shift);
            shift += 7;
        }
        return n + ((m & 0x7f) << shift);
    }

    public long readLong() throws IOException {
        long n = 0;
        int shift = 0;
        int m;
        while (((m = mIn.read()) & 0x80) != 0) {
            n += ((m & 0x7f) << shift);
            shift += 7;
        }
        return n + ((m & 0x7f) << shift);
    }

    public PayloadSize readPayloadSize() throws IOException {
        return PayloadSize.fromInteger(readInteger());
    }

    public byte readByte() throws IOException {
        return (byte)mIn.read();
    }

    public Pid readPid() throws IOException {
        return new Pid(readInteger());
    }

    public byte[] read(int len) throws IOException {
        byte[] buffer = new byte[len];
        int nBytes = 0;
        while (nBytes < len) {
            nBytes += mIn.read(buffer, nBytes, len - nBytes);
        }

        return buffer;
    }

    public String readString() throws IOException {
        int len = readInteger();
        byte[] bytes = read(len);
        return new String(bytes, "UTF-8");
    }

    static {
        mLogger = new Logging.Logger("SyscallInputStream");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
