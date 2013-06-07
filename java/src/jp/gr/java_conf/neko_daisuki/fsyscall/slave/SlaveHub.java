package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.ProtocolError;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallInputStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallOutputStream;

public class SlaveHub extends Worker {

    private static class Peer {

        private SyscallInputStream mIn;
        private SyscallOutputStream mOut;

        public Peer(SyscallInputStream in, SyscallOutputStream out) {
            mIn = in;
            mOut = out;
        }

        public SyscallInputStream getInputStream() {
            return mIn;
        }

        public SyscallOutputStream getOutputStream() {
            return mOut;
        }

        public void close() throws IOException {
            mIn.close();
            mOut.close();
        }
    }

    private static class SlavePeer extends Peer {

        private Pid mMasterPid;

        public SlavePeer(SyscallInputStream in, SyscallOutputStream out, Pid masterPid) {
            super(in, out);
            mMasterPid = masterPid;
        }

        public Pid getMasterPid() {
            return mMasterPid;
        }
    }

    private static Logging.Logger mLogger;

    private Peer mMhub;
    private Map<Pid, SlavePeer> mSlaves;

    public SlaveHub(Application application, InputStream mhubIn, OutputStream mhubOut, InputStream slaveIn, OutputStream slaveOut) throws IOException {
        mLogger.info("a slave hub is starting.");

        mMhub = new Peer(
                new SyscallInputStream(mhubIn),
                new SyscallOutputStream(mhubOut));

        negotiateVersion();
        mLogger.info("version negotiation finished.");

        Pid masterPid = mMhub.getInputStream().readPid();
        mLogger.info(String.format("master pid is %s.", masterPid));

        mSlaves = new HashMap<Pid, SlavePeer>();
        SlavePeer slave = addSlave(slaveIn, slaveOut, masterPid);

        transportFileDescriptors(slave);
        mLogger.info("file descriptors were transfered from the slave hub.");
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

    /**
     * Closes the connection for the master hub ONLY. When this method is
     * called, all slaves are not alive. So this method ignores connections for
     * slave.
     *
     * When a slave is alive in calling this method, we will know that with an
     * exception.
     */
    public void close() throws IOException {
        mMhub.close();
    }

    public void work() throws IOException {
        mLogger.info("works of the slave hub are being processed.");

        if (mMhub.getInputStream().isReady()) {
            processMasterHub();
        }
        for (SlavePeer slave: mSlaves.values()) {
            if (slave.getInputStream().isReady()) {
                processSlave(slave);
            }
        }

        mLogger.info("works of the slave hub were finished.");
    }

    private void processSlave(SlavePeer slave) throws IOException {
        mLogger.info("the work for the slave is being processed.");

        SyscallInputStream in = slave.getInputStream();
        Command command = in.readCommand();
        PayloadSize payloadSize = in.readPayloadSize();

        String fmt = "from the slave to the master: command=%s, payloadSize=%s";
        mLogger.info(String.format(fmt, command, payloadSize));

        SyscallOutputStream out = mMhub.getOutputStream();
        out.write(command);
        out.write(slave.getMasterPid());
        out.write(payloadSize);
        out.copyInputStream(in, payloadSize);

        mLogger.info("the work for the slave was finished.");
    }

    private void processMasterHub() throws IOException {
        mLogger.info("the work for the master hub is being processed.");

        SyscallInputStream in = mMhub.getInputStream();
        Command command = in.readCommand();
        Pid pid = in.readPid();
        String fmt = "command received: command=%s, pid=%s";
        mLogger.info(String.format(fmt, command, pid));

        SyscallOutputStream out = mSlaves.get(pid).getOutputStream();

        if (command == Command.CALL_EXIT) {
            mLogger.info("executing CALL_EXIT.");

            int status = in.readInteger();
            mLogger.info(String.format("exit status is %d.", status));

            out.write(command);
            out.write(status);

            mSlaves.remove(pid).close();
            return;
        }

        PayloadSize payloadSize = in.readPayloadSize();

        fmt = "from the master to the slave: command=%s, payloadSize=%s";
        mLogger.info(String.format(fmt, command, payloadSize));

        out.write(command);
        out.write(payloadSize);
        out.copyInputStream(in, payloadSize);
    }

    private void negotiateVersion() throws IOException {
        mMhub.getOutputStream().write((byte)0);

        byte version = mMhub.getInputStream().readByte();
        if (version != 0) {
            String fmt = "requested version is not supported: %d";
            throw new ProtocolError(String.format(fmt, version));
        }
    }

    private void transportFileDescriptors(Peer slave) throws IOException {
        SyscallInputStream in = slave.getInputStream();
        int len = in.readInteger();
        byte[] data = in.read(len);

        SyscallOutputStream out = mMhub.getOutputStream();
        out.write(len);
        out.write(data);
    }

    private SlavePeer addSlave(InputStream in, OutputStream out, Pid masterPid) {
        /*
         * When fork(2) is implemented, make this method public, and call from
         * Application.
         */
        SlavePeer slave = new SlavePeer(
                new SyscallInputStream(in),
                new SyscallOutputStream(out),
                masterPid);
        mSlaves.put(masterPid, slave);
        return slave;
    }

    static {
        mLogger = new Logging.Logger("SlaveHub");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
