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
import java.util.Iterator;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.NormalizedPath;

public class Application {

    private static class Processes implements Iterable<Process> {

        private static class ProcessIterator implements Iterator<Process> {

            private Process[] mProcesses;
            private int mPosition;

            public ProcessIterator(Process[] processes) {
                mProcesses = processes;
            }

            @Override
            public boolean hasNext() {
                return mPosition < mProcesses.length;
            }

            @Override
            public Process next() {
                Process slave = mProcesses[mPosition];
                mPosition++;
                return slave;
            }

            @Override
            public void remove() {
            }
        }

        private Map<Pid, Process> mProcesses = new HashMap<Pid, Process>();

        public synchronized void add(Process process) {
            mProcesses.put(process.getPid(), process);
        }

        public Process get(Pid pid) {
            return mProcesses.get(pid);
        }

        public synchronized void remove(Pid pid) {
            mProcesses.remove(pid);
        }

        public synchronized Collection<Pid> pids() {
            return new HashSet<Pid>(mProcesses.keySet());
        }

        @Override
        public synchronized Iterator<Process> iterator() {
            Collection<Process> processes = mProcesses.values();
            return new ProcessIterator(processes.toArray(new Process[0]));
        }
    }

    private static class PidGenerator {

        private static final int MIN = 1000000;
        private static final int MAX = 1000010;

        private int mNext = MIN;
        private Collection<Integer> mUsed = new HashSet<Integer>();

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
    private SlaveHub mSlaveHub;
    private Integer mExitStatus;
    private PidGenerator mPidGenerator = new PidGenerator();

    private Object mTerminatingMonitor = new Object();
    private boolean mCancelled = false;
    private LocalBoundSockets mLocalBoundSockets = new LocalBoundSockets();
    private String mResourceDirectory;
    private ResourceFiles mResourceFiles = new ResourceFiles();

    /**
     * This is for thr_new(2) (fork(2) also uses this internally).
     */
    public Slave newSlave(PairId newPairId, Process process,
                          NormalizedPath currentDirectory, UnixFile[] files,
                          Permissions permissions, Links links,
                          Slave.Listener listener,
                          Alarm alarm) throws IOException {
        Pipe slave2hub = new Pipe();
        Pipe hub2slave = new Pipe();

        InputStream slaveIn = hub2slave.getInputStream();
        OutputStream slaveOut = slave2hub.getOutputStream();
        Slave slave = new Slave(this, process, slaveIn, slaveOut,
                                currentDirectory, files, permissions, links,
                                listener, alarm);
        process.add(slave);

        InputStream hubIn = slave2hub.getInputStream();
        OutputStream hubOut = hub2slave.getOutputStream();
        mSlaveHub.addSlave(hubIn, hubOut, newPairId);

        return slave;
    }

    /**
     * This is for fork(2).
     */
    public Slave newSlave(PairId pairId, NormalizedPath currentDirectory,
                          UnixFile[] files, Permissions permissions,
                          Links links, Slave.Listener listener,
                          Alarm alarm) throws IOException {
        Process process = new Process(mPidGenerator.next());
        addProcess(process);
        return newSlave(pairId, process, currentDirectory, files, permissions,
                        links, listener, alarm);
    }

    public int run(InputStream in, OutputStream out,
                   NormalizedPath currentDirectory, InputStream stdin,
                   OutputStream stdout, OutputStream stderr,
                   Permissions permissions, Links links,
                   Slave.Listener listener, String resourceDirectory)
                   throws IOException, InterruptedException {
        mLogger.info("starting a slave application");

        mResourceDirectory = resourceDirectory;

        Process process = new Process(mPidGenerator.next());
        Pipe slave2hub = new Pipe();
        Pipe hub2slave = new Pipe();
        Slave slave = new Slave(
                this, process,
                hub2slave.getInputStream(), slave2hub.getOutputStream(),
                currentDirectory, stdin, stdout, stderr,
                permissions, links, listener);
        addProcess(process);
        process.add(slave);
        mSlaveHub = new SlaveHub(
                this,
                in, out,
                slave2hub.getInputStream(), hub2slave.getOutputStream());

        new Thread(slave).start();
        mSlaveHub.work();
        synchronized (mTerminatingMonitor) {
            for (Pid pid: mProcesses.pids()) {
                waitChildTerminating(pid);
            }
        }

        return (!mCancelled && mExitStatus != null) ? mExitStatus.intValue()
                                                    : 255;
    }

    public void cancel() {
        mCancelled = true;
        for (Process process: mProcesses) {
            process.terminate();
        }
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

    public Process waitChildTerminating(Pid pid) throws InterruptedException {
        String tag = "wait child terminating";
        Process child = mProcesses.get(pid);
        if (child == null) {
            String fmt = "%s: the process of pid %s not found";
            mLogger.warn(String.format(fmt, tag, pid));
            return null;
        }
        synchronized (mTerminatingMonitor) {
            while (!child.isZombie()) {
                mTerminatingMonitor.wait();
            }
            String fmt = "%s: released the process of pid %s";
            mLogger.info(String.format(fmt, tag, pid));
            mProcesses.remove(pid);
            mPidGenerator.release(pid);
        }
        return child;
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
        synchronized (mTerminatingMonitor) {
            mExitStatus = mExitStatus != null ? mExitStatus
                                              : process.getExitStatus();
            if (process.isZombie()) {
                mTerminatingMonitor.notifyAll();
            }
        }
    }

    private void addProcess(Process process) {
        mProcesses.add(process);
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
