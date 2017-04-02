package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.ProtocolError;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallReadableChannel;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallWritableChannel;

class SlaveHub {

    private static class Peer {

        private SyscallReadableChannel mIn;
        private SyscallWritableChannel mOut;

        protected Peer(SyscallReadableChannel in, SyscallWritableChannel out) {
            mIn = in;
            mOut = out;
        }

        public SyscallReadableChannel getReadableChannel() {
            return mIn;
        }

        public SyscallWritableChannel getWritableChannel() {
            return mOut;
        }

        public void close() throws IOException {
            mIn.close();
            mOut.close();
        }
    }

    private static class Mhub extends Peer {

        public Mhub(SyscallReadableChannel in, SyscallWritableChannel out) {
            super(in, out);
        }
    }

    private static class NewSlave extends Peer {

        private PairId mPairId;

        public NewSlave(SyscallReadableChannel in, SyscallWritableChannel out,
                        PairId pairId) {
            super(in, out);
            mPairId = pairId;
        }

        public PairId getPairId() {
            return mPairId;
        }
    }

    private static class RunningSlave extends Peer {

        private PairId mPairId;

        public RunningSlave(NewSlave slave) {
            super(slave.getReadableChannel(), slave.getWritableChannel());
            mPairId = slave.getPairId();
        }

        public PairId getPairId() {
            return mPairId;
        }
    }

    private enum SelectableAttachmentType {
        MHUB,
        SLAVE
    }

    private abstract static class SelectableAttachment {

        public abstract SelectableAttachmentType getType();

        public RunningSlave getSlave() {
            return null;
        }
    }

    private static class MhubSelectableAttachment extends SelectableAttachment {

        public SelectableAttachmentType getType() {
            return SelectableAttachmentType.MHUB;
        }
    }

    private static class SlaveSelectableAttachment extends SelectableAttachment {

        private RunningSlave mSlave;

        public SlaveSelectableAttachment(RunningSlave slave) {
            mSlave = slave;
        }

        public SelectableAttachmentType getType() {
            return SelectableAttachmentType.SLAVE;
        }

        public RunningSlave getSlave() {
            return mSlave;
        }
    }

    private static Logging.Logger mLogger;

    private Mhub mMhub;
    private Map<PairId, RunningSlave> mSlaves;
    private Set<NewSlave> mNewSlaves;
    private Set<PairId> mDeadSlaves;

    private Selector mSelector;
    private Alarm mAlarm;

    public SlaveHub(Application application, SyscallReadableChannel mhubIn,
                    SyscallWritableChannel mhubOut,
                    SyscallReadableChannel slaveIn,
                    SyscallWritableChannel slaveOut) throws IOException {
        mLogger.info("a slave hub is starting.");

        mSelector = Selector.open();
        mAlarm = application.getAlarm();

        mMhub = new Mhub(mhubIn, mhubOut);
        mhubIn.register(mSelector, new MhubSelectableAttachment());

        negotiateVersion();
        mLogger.verbose("version negotiation finished.");

        PairId firstPairId = mhubIn.readPairId();
        mLogger.info("the first pair id is %s.", firstPairId);

        mSlaves = new HashMap<PairId, RunningSlave>();
        mNewSlaves = new HashSet<NewSlave>();
        mDeadSlaves = new HashSet<PairId>();
        NewSlave slave = addSlave(slaveIn, slaveOut, firstPairId);

        transportFileDescriptors(slave);
        mLogger.verbose("file descriptors were transfered from the slave hub.");
    }

    public void work() throws IOException {
        //mLogger.verbose("works of the slave hub are being processed.");

        try {
            addNewSlaves();

            long lastSendTime = System.currentTimeMillis();
            long lastRecvTime = lastSendTime;

            while (0 < mSlaves.size()) {
                long nextKeepAliveTime = lastSendTime + 60 * 1000;
                long abortTime = lastRecvTime + 4 * 60 * 1000;
                long now = System.currentTimeMillis();
                long timeout = Math.max(Math.min(nextKeepAliveTime - now,
                                                 abortTime - now),
                                        0);
                mSelector.select(timeout);
                Set<SelectionKey> keys = mSelector.selectedKeys();

                if (keys.size() == 0) {
                    long now2 = System.currentTimeMillis();
                    if (abortTime <= now2) {
                        for (Peer slave: mSlaves.values()) {
                            slave.close();
                        }
                        throw new IOException("timeout");
                    }
                    if (nextKeepAliveTime <= now2) {
                        writeKeepAlive();
                        lastSendTime = System.currentTimeMillis();
                    }
                    continue;
                }

                for (SelectionKey key: keys) {
                    Object o = key.attachment();
                    SelectableAttachment a = (SelectableAttachment)o;
                    SelectableAttachmentType type = a.getType();
                    switch (type) {
                    case MHUB:
                        processMasterHub();
                        lastRecvTime = System.currentTimeMillis();
                        break;
                    case SLAVE:
                        processSlave(a.getSlave());
                        lastSendTime = System.currentTimeMillis();
                        break;
                    default:
                        String fmt = "invalid attachment type: %s";
                        throw new Error(String.format(fmt, type));
                    }
                }
                keys.clear();

                removeDeadSlaves();
                addNewSlaves();
            }
        }
        finally {
            close();
        }

        //mLogger.verbose("works of the slave hub were finished.");
    }

    public NewSlave addSlave(SyscallReadableChannel in,
                             SyscallWritableChannel out, PairId pairId) {
        NewSlave slave = new NewSlave(in, out, pairId);
        synchronized (mNewSlaves) {
            mNewSlaves.add(slave);
        }
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

    private void writeKeepAlive() throws IOException {
        mMhub.getWritableChannel().write(Command.KEEPALIVE);
    }

    private void addNewSlaves() throws ClosedChannelException {
        synchronized (mNewSlaves) {
            for (NewSlave newSlave: mNewSlaves) {
                RunningSlave slave = new RunningSlave(newSlave);
                SyscallReadableChannel in = slave.getReadableChannel();
                in.register(mSelector, new SlaveSelectableAttachment(slave));
                mSlaves.put(slave.getPairId(), slave);
            }
            mNewSlaves.clear();
        }
    }

    private void processSignaled(RunningSlave slave) throws IOException {
        byte signum = slave.getReadableChannel().readByte();
        PairId pairId = slave.getPairId();

        String fmt = "processing SIGNALED: pairId=%s, signal=%d (%s)";
        mLogger.debug(fmt, pairId, signum, Signal.toString(signum));

        SyscallWritableChannel out = mMhub.getWritableChannel();
        out.write(Command.SIGNALED);
        out.write(pairId);
        out.write(signum);

        Signal sig;
        try {
            sig = Signal.valueOf(signum);
        }
        catch (UnixException unused) {
            return;
        }
        if (Signal.SIGKILL.equals(sig)) {
            removeSlave(pairId);
        }
    }

    private void processSlave(RunningSlave slave) throws IOException {
        //mLogger.verbose("the work for the slave is being processed.");
        PairId pairId = slave.getPairId();

        SyscallReadableChannel in = slave.getReadableChannel();
        Command command = in.readCommand();
        if (command == Command.SIGNALED) {
            processSignaled(slave);
            return;
        }
        PayloadSize payloadSize = in.readPayloadSize();

        //String fmt = "from the slave to the master: pairId=%s, command=%s, payloadSize=%s";
        //mLogger.debug(String.format(fmt, pairId, command, payloadSize));

        SyscallWritableChannel out = mMhub.getWritableChannel();
        out.write(command);
        out.write(pairId);
        out.write(payloadSize);
        out.copy(in, payloadSize);

        //mLogger.verbose("the work for the slave was finished.");
    }

    private void disposeCommand(SyscallReadableChannel in,
                                Command command) throws IOException {
        switch (command) {
            case EXIT_CALL:
                in.readInteger();
                break;
            case THR_EXIT_CALL:
            case POLL_END:
                break;
            default:
                in.read(in.readPayloadSize());
                break;
        }
    }

    private void processMasterHub() throws IOException {
        //mLogger.verbose("the work for the master hub is being processed.");

        SyscallReadableChannel in = mMhub.getReadableChannel();
        Command command = in.readCommand();
        if (command == Command.KEEPALIVE) {
            return;
        }

        PairId pairId = in.readPairId();
        //String fmt = "command received: pairId=%s, command=%s";
        //mLogger.debug(String.format(fmt, pairId, command));

        RunningSlave slave = mSlaves.get(pairId);
        if (slave == null) {
            disposeCommand(in, command);
            return;
        }

        SyscallWritableChannel out = slave.getWritableChannel();

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
        out.copy(in, payloadSize);
    }

    private void negotiateVersion() throws IOException {
        mMhub.getWritableChannel().write((byte)0);

        byte version = mMhub.getReadableChannel().readByte();
        if (version != 0) {
            String fmt = "requested version is not supported: %d";
            throw new ProtocolError(String.format(fmt, version));
        }
    }

    private void removeDeadSlaves() throws IOException {
        for (PairId pairId: mDeadSlaves) {
            mLogger.info("remove slave: pairId=%s", pairId);
            mSlaves.remove(pairId).close();
        }
        mDeadSlaves.clear();
    }

    private void removeSlave(PairId pairId) {
        mDeadSlaves.add(pairId);
    }

    private void transportFileDescriptors(Peer slave) throws IOException {
        SyscallReadableChannel in = slave.getReadableChannel();
        int len = in.readInteger();
        byte[] data = in.read(len);

        SyscallWritableChannel out = mMhub.getWritableChannel();
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
