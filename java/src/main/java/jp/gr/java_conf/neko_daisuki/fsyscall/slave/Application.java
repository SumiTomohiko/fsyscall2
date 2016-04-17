package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.NormalizedPath;

public class Application {

    private static class PidGenerator {

        private static final int MIN = 1000000;
        private static final int MAX = 2000000;

        private int mNext = MIN;
        private Collection<Integer> mUsed = new HashSet<Integer>();

        public synchronized void use(Pid pid) {
            mUsed.add(pid.toInteger());
        }

        public synchronized Pid next() {
            int pid = mNext;
            while (mUsed.contains(Integer.valueOf(pid))) {
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

    private static class LocalBoundSockets {

        private Map<NormalizedPath, Object> mSockets;

        public LocalBoundSockets() {
            mSockets = new HashMap<NormalizedPath, Object>();
        }

        public void bind(NormalizedPath path,
                         Object socket) throws UnixException {
            synchronized (mSockets) {
                if (mSockets.get(path) != null) {
                    throw new UnixException(Errno.EADDRINUSE);
                }
                mSockets.put(path, socket);
            }
        }

        public Object get(NormalizedPath path) throws UnixException {
            Object socket;
            synchronized (mSockets) {
                socket = mSockets.get(path);
            }
            if (socket == null) {
                throw new UnixException(Errno.ENOENT);
            }
            return socket;
        }

        public void unlink(NormalizedPath path) throws UnixException {
            Object socket;
            synchronized (mSockets) {
                socket = mSockets.remove(path);
            }
            if (socket == null) {
                throw new UnixException(Errno.ENOENT);
            }
        }
    }

    private class ResourceFiles {

        private void copy(File file, URL url) throws IOException {
            InputStream in = url.openStream();
            try {
                BufferedInputStream bin = new BufferedInputStream(in);
                try {
                    OutputStream out = new FileOutputStream(file);
                    try {
                        byte buf[] = new byte[4096];
                        int nBytes;
                        while ((nBytes = bin.read(buf)) != -1) {
                            out.write(buf, 0, nBytes);
                        }
                    }
                    finally {
                        out.close();
                    }
                }
                finally {
                    bin.close();
                }
            }
            finally {
                in.close();
            }
        }

        public synchronized String getPath(URL url) throws IOException {
            String name = String.format("%08x", url.hashCode());
            File file = new File(mResourceDirectory, name);
            if (!file.exists()) {
                copy(file, url);
            }
            return file.getAbsolutePath();
        }
    }

    private static Logging.Logger mLogger;

    private Processes mProcesses = new Processes();
    private Processes mZombies = new Processes();
    private Process mInit;
    private SlaveHub mSlaveHub;
    private int mExitStatus;
    private PidGenerator mPidGenerator = new PidGenerator();

    private boolean mCancelled = false;
    private LocalBoundSockets mLocalBoundSockets = new LocalBoundSockets();
    private String mResourceDirectory;
    private ResourceFiles mResourceFiles = new ResourceFiles();
    private Alarm mAlarm = new Alarm();     // kind of giant lock

    /**
     * This is for thr_new(2) (fork(2) also uses this internally).
     */
    public Slave newSlave(PairId newPairId, Process process,
                          NormalizedPath currentDirectory,
                          Permissions permissions, Links links,
                          Slave.Listener listener) throws IOException {
        Pipe slave2hub = new Pipe();
        Pipe hub2slave = new Pipe();

        InputStream slaveIn = hub2slave.getInputStream();
        OutputStream slaveOut = slave2hub.getOutputStream();
        Slave slave = new Slave(this, process, slaveIn, slaveOut,
                                currentDirectory, permissions, links, listener);
        process.add(slave);

        InputStream hubIn = slave2hub.getInputStream();
        OutputStream hubOut = hub2slave.getOutputStream();
        mSlaveHub.addSlave(hubIn, hubOut, newPairId);

        return slave;
    }

    /**
     * This is for fork(2).
     */
    public Slave newProcess(PairId pairId, Process parent,
                            NormalizedPath currentDirectory,
                            Permissions permissions, Links links,
                            Slave.Listener listener) throws IOException {
        Pid pid = mPidGenerator.next();
        Process process = new Process(pid, parent, parent.dupFileTable());
        parent.addChild(process);
        addProcess(process);
        return newSlave(pairId, process, currentDirectory, permissions, links,
                        listener);
    }

    public int run(InputStream in, OutputStream out,
                   NormalizedPath currentDirectory, InputStream stdin,
                   OutputStream stdout, OutputStream stderr,
                   Permissions permissions, Links links,
                   Slave.Listener listener, String resourceDirectory)
                   throws IOException, InterruptedException {
        mLogger.info("starting a slave application");

        mResourceDirectory = resourceDirectory;

        initializeInitProcess();

        Process process = new Process(mPidGenerator.next(), mInit);
        mInit.addChild(process);
        addProcess(process);

        Pipe slave2hub = new Pipe();
        Pipe hub2slave = new Pipe();
        Slave slave = new Slave(
                this, process,
                hub2slave.getInputStream(), slave2hub.getOutputStream(),
                currentDirectory, stdin, stdout, stderr,
                permissions, links, listener);
        process.add(slave);

        mSlaveHub = new SlaveHub(
                this,
                in, out,
                slave2hub.getInputStream(), hub2slave.getOutputStream());

        new Thread(slave).start();
        mSlaveHub.work();
        synchronized (mAlarm) {
            while (!mProcesses.isEmpty()) {
                mAlarm.wait();
            }
        }

        return !mCancelled ? mExitStatus : 255;
    }

    public void cancel() {
        mCancelled = true;
        for (Process process: mProcesses) {
            process.terminate();
        }
    }

    public Alarm getAlarm() {
        return mAlarm;
    }

    /**
     * Binds a Unix domain socket to a path. This method handles a socket as an
     * Object instance, because I dislike disclosing the Slave.Socket class.
     */
    public void bindSocket(NormalizedPath path, Object socket) throws UnixException {
        mLocalBoundSockets.bind(path, socket);
    }

    /**
     * Returns a socket bound to a given path. This method returns an Object.
     * Callers have responsibility to cast it to Slave.Socket.
     */
    public Object getUnixDomainSocket(NormalizedPath path) throws UnixException {
        return mLocalBoundSockets.get(path);
    }

    public void unlinkUnixDomainNode(NormalizedPath path) throws UnixException {
        mLocalBoundSockets.unlink(path);
    }

    public boolean pollChildTermination(Pid pid) throws UnixException {
        Process process;
        synchronized (mAlarm) {
            process = findZombie(pid);
        }
        if (process == null) {
            return false;
        }
        releaseProcess(process);
        return true;
    }

    public void kill(Pid pid, Signal sig) throws UnixException {
        Process process = mProcesses.get(pid);
        if (process == null) {
            throw new UnixException(Errno.ESRCH);
        }
        process.kill(sig);
    }

    public String getResourcePath(URL url) throws IOException {
        return mResourceFiles.getPath(url);
    }

    public void onSlaveTerminated(Process process) {
        synchronized (mAlarm) {
            mExitStatus = process.getExitStatus();
            if (!process.isRunning()) {
                mProcesses.remove(process);
                mZombies.add(process);
                mAlarm.alarm();
            }
        }
    }

    private void releaseProcess(Process process) {
        process.getParent().removeChild(process);
        for (Process child: process.getChildren()) {
            mInit.addChild(child);
            child.setParent(mInit);
        }

        Pid pid = process.getPid();
        mPidGenerator.release(pid);
        mLogger.info("released the process of pid %s", pid);
    }

    private void addProcess(Process process) {
        mProcesses.add(process);
    }

    private void initializeInitProcess() {
        Pid pid = new Pid(1);
        mPidGenerator.use(pid);
        mInit = new Process(pid);
    }

    private Process findZombie(Pid pid) throws UnixException {
        Process process = mZombies.remove(pid);
        if (process != null) {
            return process;
        }
        if (!mProcesses.contains(pid)) {
            // Another thread got the zombie.
            throw new UnixException(Errno.ECHILD);
        }
        return null;
    }

    private static void usage(PrintStream out) {
        out.println("usage: Main rfd wfd currentDirectory resourceDirectory");
    }

    private static void deleteDirectory(String path) {
        File file = new File(path);
        File children[] = file.listFiles();
        int nChildren = children.length;
        for (int i = 0; i < nChildren; i++) {
            File f = children[i];
            if (f.isDirectory()) {
                deleteDirectory(f.getPath());
                continue;
            }
            f.delete();
        }
        file.delete();
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
        mLogger.info("================================");

        int rfd, wfd;
        try {
            rfd = Integer.parseInt(args[0]);
            wfd = Integer.parseInt(args[1]);
        }
        catch (ArrayIndexOutOfBoundsException unused) {
            Application.usage(System.out);
            System.exit(1);
            return;
        }
        catch (NumberFormatException unused) {
            Application.usage(System.out);
            System.exit(1);
            return;
        }
        String fdFormat = "/dev/fd/%d";
        String inPath = String.format(fdFormat, new Integer(rfd));
        String outPath = String.format(fdFormat, new Integer(wfd));
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

        Calendar now = Calendar.getInstance();
        String resourceFormat = "/tmp/slave.resource.%04d%02d%02d%02d%02d%02d";
        String resourceDir = String.format(resourceFormat,
                                           now.get(Calendar.YEAR),
                                           now.get(Calendar.MONTH) + 1,
                                           now.get(Calendar.DAY_OF_MONTH),
                                           now.get(Calendar.HOUR_OF_DAY),
                                           now.get(Calendar.MINUTE),
                                           now.get(Calendar.SECOND));
        if (!new File(resourceDir).mkdir()) {
            String messageFormat = "cannot make the resource directory: %s\n";
            System.err.format(messageFormat, resourceDir);
            System.exit(32);
        }
        int exitStatus;
        try {
            Application app = new Application();
            InputStream stdin = System.in;
            OutputStream stdout = System.out;
            OutputStream stderr = System.err;
            Permissions perm = new Permissions(true);
            Links links = new Links();
            try {
                exitStatus = app.run(in, out, new NormalizedPath(args[2]),
                                     stdin, stdout, stderr, perm, links, null,
                                     resourceDir);
            }
            catch (Throwable e) {
                e.printStackTrace();
                exitStatus = 1;
            }
        }
        finally {
            deleteDirectory(resourceDir);
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
