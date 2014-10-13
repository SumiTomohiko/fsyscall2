package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;

public class Application {

    private static class ZombieSlaves {

        private Map<Pid, Slave> mSlaves = new HashMap<Pid, Slave>();

        public synchronized void add(Slave slave) {
            mSlaves.put(slave.getPid(), slave);
            notifyAll();
        }

        public synchronized Slave waitExit(Pid pid) throws InterruptedException {
            while (mSlaves.get(pid) == null) {
                wait();
            }
            return mSlaves.remove(pid);
        }
    }

    private static class Pipe {

        private static class PrivateInputStream extends InputStream {

            private ByteArrayOutputStream mOut;
            private ByteArrayInputStream mBuffer;

            public PrivateInputStream(ByteArrayOutputStream out) {
                mOut = out;
                mBuffer = new ByteArrayInputStream(new byte[0]);
            }

            public int read() throws IOException {
                updateBuffer();
                return mBuffer.read();
            }

            public int available() throws IOException {
                updateBuffer();
                return mBuffer.available();
            }

            private void updateBuffer() {
                if ((0 < mBuffer.available()) || (mOut.size() == 0)) {
                    return;
                }
                mBuffer = new ByteArrayInputStream(mOut.toByteArray());
                mOut.reset();
            }
        }

        private InputStream mIn;
        private OutputStream mOut;

        public Pipe() throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PrivateInputStream in = new PrivateInputStream(out);

            mIn = in;
            mOut = out;
        }

        public InputStream getInput() {
            return mIn;
        }

        public OutputStream getOutput() {
            return mOut;
        }
    }

    private static class PidGenerator {

        private static final int MIN = 1000000;
        private static final int MAX = 1000010;

        private int mNext = MIN;
        private Collection<Integer> mUsed = new HashSet<Integer>();

        public synchronized Pid generate() {
            int pid = mNext;
            while (!mUsed.contains(Integer.valueOf(pid))) {
                pid = nextOf(pid);
            }
            mNext = nextOf(pid);
            return new Pid(pid);
        }

        public synchronized void release(Pid pid) {
            mUsed.remove(Integer.valueOf(pid.toInteger()));
        }

        private int nextOf(int pid) {
            return pid < MAX ? pid + 1 : MIN;
        }
    }

    private static Logging.Logger mLogger;

    private List<Slave> mSlaves = new LinkedList<Slave>();
    private SlaveHub mSlaveHub;
    private int mExitStatus;
    private ZombieSlaves mZombieSlaves = new ZombieSlaves();
    private PidGenerator mPidGenerator = new PidGenerator();

    private Collection<Slave> mSlavesToRemove;
    private Collection<Slave> mSlavesToAdd;
    private boolean mCancelled = false;

    public Application() {
        mExitStatus = 0;
        mSlavesToRemove = new LinkedList<Slave>();
        mSlavesToAdd = new LinkedList<Slave>();
    }

    public void removeSlave(Slave slave) {
        mSlavesToRemove.add(slave);
    }

    public void addSlave(Slave slave) {
        mSlavesToAdd.add(slave);
    }

    public Slave addSlave(UnixFile[] files, Permissions permissions,
                          Links links, Slave.Listener listener) throws IOException {
        Pipe slave2hub = new Pipe();
        Pipe hub2slave = new Pipe();

        InputStream slaveIn = hub2slave.getInput();
        OutputStream slaveOut = slave2hub.getOutput();
        Slave slave = new Slave(this, mPidGenerator.generate(), slaveIn,
                                slaveOut, files, permissions, links, listener);
        addSlave(slave);

        InputStream hubIn = slave2hub.getInput();
        OutputStream hubOut = hub2slave.getOutput();
        mSlaveHub.addSlave(hubIn, hubOut, slave.getPid());

        return slave;
    }

    public void setExitStatus(int exitStatus) {
        mExitStatus = exitStatus;
    }

    public int run(InputStream in, OutputStream out, InputStream stdin, OutputStream stdout, OutputStream stderr, Permissions permissions, Links links, Slave.Listener listener) throws IOException, InterruptedException {
        mLogger.info("starting a slave application");

        Pipe slave2hub = new Pipe();
        Pipe hub2slave = new Pipe();
        Slave slave = new Slave(
                this, mPidGenerator.generate(),
                hub2slave.getInput(), slave2hub.getOutput(),
                stdin, stdout, stderr,
                permissions, links, listener);
        addSlave(slave);
        SlaveHub hub = new SlaveHub(
                this,
                in, out,
                slave2hub.getInput(), hub2slave.getOutput());
        mSlaveHub = hub;

        mLogger.verbose("the main loop starts.");

        addSlaves();
        while ((0 < mSlaves.size()) && !mCancelled) {
            waitReady();
            kickWorkers();
            removeSlaves();
            addSlaves();
        }
        hub.close();

        return !mCancelled ? mExitStatus : 255;
    }

    public void cancel() {
        mCancelled = true;
        for (Slave slave: mSlaves) {
            slave.cancel();
        }
    }

    public Slave waitExit(Pid pid) throws InterruptedException {
        return mZombieSlaves.waitExit(pid);
    }

    public void onSlaveExited(Slave slave) {
        mZombieSlaves.add(slave);
    }

    private void addSlaves() {
        for (Slave slave: mSlavesToAdd) {
            mSlaves.add(slave);
        }
        mSlavesToAdd.clear();
    }

    private void removeSlaves() {
        for (Slave slave: mSlavesToRemove) {
            mSlaves.remove(slave);
        }
        mSlavesToRemove.clear();
    }

    private void kickWorkerIfReady(Worker worker) throws IOException {
        if (!worker.isReady()) {
            return;
        }
        worker.work();
    }

    private void kickWorkers() throws IOException {
        kickWorkerIfReady(mSlaveHub);
        for (Worker worker: mSlaves) {
            kickWorkerIfReady(worker);
        }
    }

    private void waitReady() throws IOException, InterruptedException {
        while (!isReady()) {
            Thread.sleep(10 /* msec */);
        }
    }

    private boolean isReady() throws IOException {
        boolean ready = mSlaveHub.isReady();
        int size = mSlaves.size();
        for (int i = 0; (i < size) && !ready; i++) {
            ready = mSlaves.get(i).isReady();
        }
        return ready;
    }

    private static void usage(PrintStream out) {
        out.println("usage: Main rfd wfd");
    }

    /**
     * This is the tester method. This class requires two parameters -- the file
     * descriptor to read and another one to write. But, Java DOES NOT HAVE ANY
     * WAYS to make InputStream/OutputStream from file descriptor number. So
     * this method opens <code>/dev/fd/<var>rfd</var></code> and
     * <code>/dev/fd/<var>wfd</var></code> to make streams. This way is
     * available on FreeBSD 9.1 with fdescfs mounted on <code>/dev/fd</code>. I
     * do not know if the same way is usable on other platforms.
     */
    public static void main(String[] args) {
        Logging.Destination destination;
        try {
            destination = new Logging.FileDestination("fsyscall.log");
        }
        catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
            return; // This is needed to avoid the unreachable warning.
        }
        Logging.setDestination(destination);

        int rfd, wfd;
        try {
            rfd = Integer.parseInt(args[0]);
            wfd = Integer.parseInt(args[1]);
        }
        catch (ArrayIndexOutOfBoundsException _) {
            Application.usage(System.out);
            System.exit(1);
            return;
        }
        catch (NumberFormatException _) {
            Application.usage(System.out);
            System.exit(1);
            return;
        }
        String fmt = "/dev/fd/%d";
        String inPath = String.format(fmt, new Integer(rfd));
        String outPath = String.format(fmt, new Integer(wfd));
        InputStream in;
        OutputStream out;
        try {
            in = new FileInputStream(inPath);
            out = new FileOutputStream(outPath);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
            return;
        }

        int exitStatus;
        Application app = new Application();
        InputStream stdin = System.in;
        OutputStream stdout = System.out;
        OutputStream stderr = System.err;
        Permissions perm = new Permissions(true);
        Links links = new Links();
        try {
            exitStatus = app.run(in, out, stdin, stdout, stderr, perm, links, null);
        }
        catch (Throwable e) {
            e.printStackTrace();
            exitStatus = 1;
        }
        System.exit(exitStatus);
    }

    static {
        mLogger = new Logging.Logger("Application");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
