package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.Pipe;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.SignalSet;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix.IoVec;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix.TimeVal;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;

public class SyscallReadableChannel {

    private interface Source {

        public byte read() throws IOException;
        public byte[] read(int len) throws IOException;
        public SelectionKey register(Selector selector,
                                     Object attachment)
                                     throws ClosedChannelException;
        public void close() throws IOException;
        public boolean isReady() throws IOException;
    }

    private static class ChannelSource implements Source {

        private static final String DISCONNECTED_MESSAGE = "disconnected unexpectedly";

        private ReadableByteChannel mReadableChannel;
        private SelectableChannel mSelectableChannel;
        private Selector mSelector;
        private ByteBuffer mBuffer;

        public ChannelSource(ReadableByteChannel readableChannel,
                             SelectableChannel selectableChannel)
                             throws IOException {
            mReadableChannel = readableChannel;
            mSelectableChannel = selectableChannel;
            mSelector = Selector.open();
            mBuffer = ByteBuffer.allocate(1);

            mSelectableChannel.configureBlocking(false);
            mSelectableChannel.register(mSelector, SelectionKey.OP_READ);
        }

        public byte read() throws IOException {
            mBuffer.clear();
            read(mBuffer);
            mBuffer.flip();
            return mBuffer.get();
        }

        public byte[] read(int len) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(len);
            read(buffer);
            return buffer.array();
        }

        public SelectionKey register(Selector selector,
                                     Object attachment)
                                     throws ClosedChannelException {
            return mSelectableChannel.register(selector, SelectionKey.OP_READ,
                                               attachment);
        }

        public void close() throws IOException {
            mSelector.close();
            mReadableChannel.close();
        }

        public boolean isReady() throws IOException {
            return mSelector.selectNow() == 1;
        }

        private void read(ByteBuffer buffer) throws IOException {
            while (buffer.hasRemaining()) {
                switch (mReadableChannel.read(buffer)) {
                case -1:
                    throw new IOException(DISCONNECTED_MESSAGE);
                case 0:
                    break;
                default:
                    continue;
                }

                mSelector.select();
                Set<SelectionKey> keys = mSelector.selectedKeys();
                int nChannels = keys.size();
                switch (nChannels) {
                case 0:
                    throw new IOException("timeout");
                case 1:
                    break;
                default:
                    String fmt = "Selector.select() returned invalid value: %d";
                    throw new Error(String.format(fmt, nChannels));
                }
                keys.clear();

                switch (mReadableChannel.read(buffer)) {
                case -1:
                    throw new IOException(DISCONNECTED_MESSAGE);
                case 0:
                    throw new Error("cannot read channel");
                default:
                    continue;
                }
            }
        }
    }

    private static class BufferSource implements Source {

        private ByteBuffer mBuffer;

        public BufferSource(byte[] buffer) {
            mBuffer = ByteBuffer.allocate(buffer.length);
            mBuffer.put(buffer);
            mBuffer.flip();
        }

        public byte read() throws IOException {
            try {
                return mBuffer.get();
            }
            catch (BufferUnderflowException e) {
                throw new IOException("no more data in buffer");
            }
        }

        public byte[] read(int len) throws IOException {
            byte[] buffer = new byte[len];
            try {
                mBuffer.get(buffer);
            }
            catch (BufferUnderflowException e) {
                String fmt = "buffer does not have %d[byte] data, only %d[byte]";
                int remaining = mBuffer.remaining();
                throw new IOException(String.format(fmt, len, remaining));
            }
            return buffer;
        }

        public SelectionKey register(Selector selector,
                                     Object attachment)
                                     throws ClosedChannelException {
            String message = "BufferSource does not work with Selector";
            throw new UnsupportedOperationException(message);
        }

        public void close() throws IOException {
            // does nothing
        }

        public boolean isReady() throws IOException {
            return mBuffer.hasRemaining();
        }
    }

    //private static Logging.Logger mLogger;

    private Source mSource;

    public SyscallReadableChannel(Pipe.SourceChannel pipe) throws IOException {
        this(pipe, pipe);
    }

    public SyscallReadableChannel(SocketChannel socket) throws IOException {
        this(socket, socket);
    }

    public SyscallReadableChannel(byte[] buffer) throws IOException {
        mSource = new BufferSource(buffer);
    }

    private SyscallReadableChannel(ReadableByteChannel readableChannel,
                                   SelectableChannel selectableChannel) throws IOException {
        mSource = new ChannelSource(readableChannel, selectableChannel);
    }

    public SelectionKey register(Selector selector) throws ClosedChannelException {
        return register(selector, null);
    }

    public SelectionKey register(Selector selector, Object attachment) throws ClosedChannelException {
        return mSource.register(selector, attachment);
    }

    public PayloadSize readPayloadSize() throws IOException {
        return PayloadSize.fromInteger(readInteger());
    }

    public byte[] read(int len) throws IOException {
        return mSource.read(len);
    }

    public byte[] read(PayloadSize len) throws IOException {
        return read(len.toInteger());
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

    public byte readByte() throws IOException {
        return mSource.read();
    }

    public PairId readPairId() throws IOException {
        return new PairId(readInteger());
    }

    public Pid readPid() throws IOException {
        return new Pid(readInteger());
    }

    public Command readCommand() throws IOException {
        return Command.fromInteger(readInteger());
    }

    public TimeVal readTimeVal() throws IOException {
        TimeVal tv = new TimeVal();
        tv.tv_sec = readLong();
        tv.tv_usec = readLong();
        return tv;
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

    public void close() throws IOException {
        mSource.close();
    }

    /**
     * This method is not cool, but poll(2) needs this method.
     */
    public boolean isReady() throws IOException {
        return mSource.isReady();
    }

    static {
        //mLogger = new Logging.Logger("SyscallReadableChannel");
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
