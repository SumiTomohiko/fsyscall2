package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.HashSet;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.Sigaction;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.SignalSet;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix.IoVec;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;

public class SyscallInputStream {

    private enum Status {
        OPEN,
        CLOSED
    };

    private static final Sigaction.Handler[] ACTCODE2HANDLER = new Sigaction.Handler[] {
        Sigaction.Handler.DEFAULT,
        Sigaction.Handler.IGNORE,
        Sigaction.Handler.ACTIVE
    };

    //private static Logging.Logger mLogger;

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
        //String fmt = "numeric representation of the command is %d.";
        //mLogger.debug(String.format(fmt, n));

        //Command command = Command.fromInteger(n);
        //mLogger.debug(String.format("command is %s.", command));

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
        while (((m = readByte()) & 0x80) != 0) {
            n += ((m & 0x7f) << shift);
            shift += 7;
        }
        return n + ((m & 0x7f) << shift);
    }

    public short readShort() throws IOException {
        short n = 0;
        int shift = 0;
        byte m;
        while (((m = readByte()) & 0x80) != 0) {
            n += ((m & 0x7f) << shift);
            shift += 7;
        }
        return (short)(n + ((m & 0x7f) << shift));
    }

    public long readLong() throws IOException {
        long n = 0;
        int shift = 0;
        int m;
        while (((m = readByte()) & 0x80) != 0) {
            n += ((m & 0x7f) << shift);
            shift += 7;
        }
        return n + ((m & 0x7f) << shift);
    }

    public PayloadSize readPayloadSize() throws IOException {
        return PayloadSize.fromInteger(readInteger());
    }

    public byte readByte() throws IOException {
        int n = mIn.read();
        if ((n < 0) || (255 < n)) {
            throw new IOException("disconnected unexpectedly");
        }
        return (byte)n;
    }

    public PairId readPairId() throws IOException {
        return new PairId(readInteger());
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

    public IoVec readIoVec() throws IOException {
        IoVec iovec = new IoVec();
        long len = readLong();
        iovec.iov_len = len;
        iovec.iov_base = read((int)len);
        return iovec;
    }

    public SignalSet readSignalSet() throws IOException, UnixException {
        Collection<Signal> c = new HashSet<Signal>();

        for (int index = 0; index < 4; index++) {
            long bits = readLong();
            for (int bit = 0; bit < 32; bit++) {
                if ((bits & (1 << bit)) == 0) {
                    continue;
                }
                Signal signal;
                try {
                    signal = Signal.valueOf(32 * index + bit + 1);
                }
                catch (UnixException e) {
                    /*
                     * sigfillset(3) sets unused bits. Ignore these.
                     */
                    continue;
                }
                c.add(signal);
            }
        }

        return new SignalSet(c);
    }

    public Sigaction readSigaction() throws IOException, UnixException {
        Sigaction act = new Sigaction();

        act.sa_handler = ACTCODE2HANDLER[readInteger()];
        act.sa_flags = readInteger();
        act.sa_mask = readSignalSet();

        return act;
    }

    static {
        //mLogger = new Logging.Logger("SyscallInputStream");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
