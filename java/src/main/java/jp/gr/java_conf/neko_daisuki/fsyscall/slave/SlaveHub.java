package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.ProtocolError;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallInputStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallOutputStream;

class SlaveHub {

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

        private PairId mPairId;

        public SlavePeer(SyscallInputStream in, SyscallOutputStream out,
                         PairId pairId) {
            super(in, out);
            mPairId = pairId;
        }

        public PairId getPairId() {
            return mPairId;
        }
    }

    private static Logging.Logger mLogger;

    private Peer mMhub;
    private Map<PairId, SlavePeer> mSlaves;
    private Map<PairId, SlavePeer> mNewSlaves;

    private Alarm mAlarm;

    public SlaveHub(Application application, InputStream mhubIn, OutputStream mhubOut, InputStream slaveIn, OutputStream slaveOut) throws IOException {
        mLogger.info("a slave hub is starting.");

        mAlarm = application.getAlarm();

        mMhub = new Peer(
                new SyscallInputStream(mhubIn),
                new SyscallOutputStream(mhubOut));

        negotiateVersion();
        mLogger.verbose("version negotiation finished.");

        PairId firstPairId = mMhub.getInputStream().readPairId();
        mLogger.info("the first pair id is %s.", firstPairId);

        mSlaves = new HashMap<PairId, SlavePeer>();
        mNewSlaves = Collections.synchronizedMap(new HashMap<PairId, SlavePeer>());
        SlavePeer slave = addSlave(slaveIn, slaveOut, firstPairId);

        transportFileDescriptors(slave);
        mLogger.verbose("file descriptors were transfered from the slave hub.");
    }

    public void work() throws IOException {
        //mLogger.verbose("works of the slave hub are being processed.");

        try {
            addNewSlaves();

            while (0 < mSlaves.size()) {
                if (mMhub.getInputStream().isReady()) {
                    processMasterHub();
                }
                for (SlavePeer slave: mSlaves.values()) {
                    if (slave.getInputStream().isReady()) {
                        processSlave(slave);
                    }
                }
                try {
                    Thread.sleep(10 /* msec */);
                }
                catch (InterruptedException unused) {
                    break;
                }

                addNewSlaves();
            }
        }
        finally {
            close();
        }

        //mLogger.verbose("works of the slave hub were finished.");
    }

    public SlavePeer addSlave(InputStream in, OutputStream out, PairId pairId) {
        SlavePeer slave = new SlavePeer(
                new SyscallInputStream(in),
                new SyscallOutputStream(out),
                pairId);
        mNewSlaves.put(pairId, slave);
        return slave;
    }

    /**
     * Closes the connection for the master hub ONLY. When this method is
     * called, all slaves are not alive. So this method ignores connections for
     * slave.
     *
     * When a slave is alive in calling this method, we will know that with an
     * exception.
     */
    private void close() throws IOException {
        mMhub.close();
    }

    private void addNewSlaves() {
        for (PairId pairId: mNewSlaves.keySet()) {
            mSlaves.put(pairId, mNewSlaves.get(pairId));
        }
        mNewSlaves.clear();
    }

    private void processSignaled(SlavePeer slave) throws IOException {
        byte signum = slave.getInputStream().readByte();

        String fmt = "processing SIGNALED: signal=%d (%s)";
        mLogger.debug(fmt, signum, Signal.toString(signum));

        SyscallOutputStream out = mMhub.getOutputStream();
        out.write(Command.SIGNALED);
        out.write(slave.getPairId());
        out.write(signum);
    }

    private void processSlave(SlavePeer slave) throws IOException {
        //mLogger.verbose("the work for the slave is being processed.");

        SyscallInputStream in = slave.getInputStream();
        Command command = in.readCommand();
        if (command == Command.SIGNALED) {
            processSignaled(slave);
            return;
        }
        PayloadSize payloadSize = in.readPayloadSize();

        //String fmt = "from the slave to the master: command=%s, payloadSize=%s";
        //mLogger.debug(String.format(fmt, command, payloadSize));

        SyscallOutputStream out = mMhub.getOutputStream();
        out.write(command);
        out.write(slave.getPairId());
        out.write(payloadSize);
        out.copyInputStream(in, payloadSize);

        //mLogger.verbose("the work for the slave was finished.");
    }

    private void processMasterHub() throws IOException {
        //mLogger.verbose("the work for the master hub is being processed.");

        SyscallInputStream in = mMhub.getInputStream();
        Command command = in.readCommand();
        PairId pairId = in.readPairId();
        //String fmt = "command received: command=%s, pairId=%s";
        //mLogger.debug(String.format(fmt, command, pairId));

        SyscallOutputStream out = mSlaves.get(pairId).getOutputStream();

        switch (command) {
        case EXIT_CALL:
            mLogger.verbose("executing EXIT_CALL.");

            int status = in.readInteger();
            mLogger.info("exit status is %d.", status);

            out.write(command);
            out.write(status);

            removeSlave(pairId);
            return;
        case THR_EXIT_CALL:
            mLogger.verbose("executing %s", command);
            out.write(command);
            removeSlave(pairId);
            return;
        case POLL_END:
            mLogger.verbose("executing %s", command);
            out.write(command);
            synchronized (mAlarm) {
                mAlarm.alarm();
            }
            return;
        default:
            break;
        }

        PayloadSize payloadSize = in.readPayloadSize();

        //fmt = "from the master to the slave: command=%s, payloadSize=%s";
        //mLogger.debug(String.format(fmt, command, payloadSize));

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

    private void removeSlave(PairId pairId) throws IOException {
        mSlaves.remove(pairId).close();
    }

    private void transportFileDescriptors(Peer slave) throws IOException {
        SyscallInputStream in = slave.getInputStream();
        int len = in.readInteger();
        byte[] data = in.read(len);

        SyscallOutputStream out = mMhub.getOutputStream();
        out.write(len);
        out.write(data);
    }

    static {
        mLogger = new Logging.Logger("SlaveHub");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
