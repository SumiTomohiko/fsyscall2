package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.ProtocolError;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.InputSyscallStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.OutputSyscallStream;

public class SlaveHub extends Worker {

    private static class Peer {

        private InputSyscallStream mIn;
        private OutputSyscallStream mOut;

        public Peer(InputSyscallStream in, OutputSyscallStream out) {
            mIn = in;
            mOut = out;
        }

        public InputSyscallStream getInputStream() {
            return mIn;
        }

        public OutputSyscallStream getOutputStream() {
            return mOut;
        }
    }

    private Application mApplication;
    private Peer mMhub;
    private Map<Pid, Peer> mSlaves;

    public SlaveHub(Application application, InputStream mhubIn, OutputStream mhubOut, InputStream slaveIn, OutputStream slaveOut) throws IOException {
        mApplication = application;
        mMhub = new Peer(
                new InputSyscallStream(mhubIn),
                new OutputSyscallStream(mhubOut));

        negotiateVersion();
        Pid masterPid = mMhub.getInputStream().readPid();

        mSlaves = new HashMap<Pid, Peer>();
        Peer slave = new Peer(
                new InputSyscallStream(slaveIn),
                new OutputSyscallStream(slaveOut));
        mSlaves.put(masterPid, slave);

        transportFileDescriptors(slave);
    }

    public boolean isReady() throws IOException {
        if (mMhub.getInputStream().isReady()) {
            return true;
        }
        for (Peer slave: mSlaves.values()) {
            if (slave.getInputStream().isReady()) {
                return true;
            }
        }
        return false;
    }

    public void work() throws IOException {
        if (mMhub.getInputStream().isReady()) {
            // TODO
        }
        for (Peer peer: mSlaves.values()) {
            if (peer.getInputStream().isReady()) {
                // TODO
            }
        }
    }

    private void negotiateVersion() throws IOException {
        byte version = mMhub.getInputStream().readByte();
        if (version != 0) {
            String fmt = "requested version is not supported: %d";
            throw new ProtocolError(String.format(fmt, version));
        }
        mMhub.getOutputStream().writeByte((byte)0);
    }

    private void transportFileDescriptors(Peer slave) throws IOException {
        InputSyscallStream in = slave.getInputStream();
        int len = in.readInteger();
        byte[] data = in.read(len);

        OutputSyscallStream out = slave.getOutputStream();
        out.writeInteger(len);
        out.write(data);
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
