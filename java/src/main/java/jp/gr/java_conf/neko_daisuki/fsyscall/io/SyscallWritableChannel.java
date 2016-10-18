package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;

public class SyscallWritableChannel {

    private WritableByteChannel mChannel;

    public SyscallWritableChannel(WritableByteChannel channel) {
        mChannel = channel;
    }

    public void write(byte n) throws IOException {
        write(new byte[] { n });
    }

    public void write(int n) throws IOException {
        write(Encoder.encodeInteger(n));
    }

    public void write(PayloadSize size) throws IOException {
        write(size.toInteger());
    }

    public void write(byte[] buffer) throws IOException {
        ByteBuffer b = ByteBuffer.wrap(buffer);
        while (b.hasRemaining()) {
            mChannel.write(b);
        }
    }

    public void write(Command command) throws IOException {
        write(command.toInteger());
    }

    public void write(PairId pairId) throws IOException {
        write(pairId.toInteger());
    }

    public void write(Pid pid) throws IOException {
        write(pid.toInteger());
    }

    public void copy(SyscallReadableChannel in, PayloadSize size) throws IOException {
        int rest = size.toInteger();
        while (0 < rest) {
            int nBytes = Math.min(rest, 8192);
            write(in.read(nBytes));
            rest -= nBytes;
        }
    }

    public void close() throws IOException {
        mChannel.close();
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
