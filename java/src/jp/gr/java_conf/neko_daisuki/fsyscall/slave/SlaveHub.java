package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.io.InputSyscallStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.OutputSyscallStream;

public class SlaveHub extends Worker {

    private static class Peer {

        public InputSyscallStream in;
        public OutputSyscallStream out;

        public Peer(InputSyscallStream in, OutputSyscallStream out) {
            this.in = in;
            this.out = out;
        }
    }

    private Peer mMhub;
    private Peer mSlave;

    public SlaveHub(InputStream mhubIn, OutputStream mhubOut, InputStream slaveIn, OutputStream slaveOut) {
        mMhub = new Peer(
                new InputSyscallStream(mhubIn),
                new OutputSyscallStream(mhubOut));
        mSlave = new Peer(
                new InputSyscallStream(slaveIn),
                new OutputSyscallStream(slaveOut));
    }

    public boolean isReady() throws IOException {
        return mMhub.in.isReady() || mSlave.in.isReady();
    }

    public void work() {
        // TODO
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
