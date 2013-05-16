package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;

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

    private Application mApplication;
    private Peer mMhub;
    private List<Peer> mSlaves;

    public SlaveHub(Application application, InputStream mhubIn, OutputStream mhubOut, InputStream slaveIn, OutputStream slaveOut) {
        mApplication = application;
        mMhub = new Peer(
                new InputSyscallStream(mhubIn),
                new OutputSyscallStream(mhubOut));
        mSlaves = new LinkedList<Peer>();
        mSlaves.add(
                new Peer(
                    new InputSyscallStream(slaveIn),
                    new OutputSyscallStream(slaveOut)));
    }

    public boolean isReady() throws IOException {
        if (mMhub.in.isReady()) {
            return true;
        }
        for (Peer peer: mSlaves) {
            if (peer.in.isReady()) {
                return true;
            }
        }
        return false;
    }

    public void work() {
        // TODO
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
