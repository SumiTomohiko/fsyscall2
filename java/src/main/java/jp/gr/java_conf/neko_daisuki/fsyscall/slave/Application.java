package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URL;
import java.nio.channels.Pipe;
import java.nio.channels.SocketChannel;
import java.security.GeneralSecurityException;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import javax.net.ssl.SSLContext;

import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SSLFrontEnd;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallReadableChannel;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallWritableChannel;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.PhysicalPath;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.SSLUtil;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.VirtualPath;

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

        private Map<PhysicalPath, Object> mSockets;

        public LocalBoundSockets() {
            mSockets = new HashMap<PhysicalPath, Object>();
        }

        public void bind(PhysicalPath path,
                         Object socket) throws UnixException {
            synchronized (mSockets) {
                if (mSockets.get(path) != null) {
                    throw new UnixException(Errno.EADDRINUSE);
                }
                mSockets.put(path, socket);
            }
        }

        public Object get(PhysicalPath path) throws UnixException {
            Object socket;
            synchronized (mSockets) {
                socket = mSockets.get(path);
            }
            if (socket == null) {
                throw new UnixException(Errno.ENOENT);
            }
            return socket;
        }

        public void unlink(PhysicalPath path) throws UnixException {
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

    private interface MainCleanUp {

        public void run();
    }

    private static class NopMainCleanUp implements MainCleanUp {

        public void run() {
        }
    }

    private static class SSLMainCleanUp implements MainCleanUp {

        private SSLFrontEnd mSSLFrontEnd;

        public SSLMainCleanUp(SSLFrontEnd sslFrontEnd) {
            mSSLFrontEnd = sslFrontEnd;
        }

        public void run() {
            try {
                mSSLFrontEnd.join();
            }
            catch (InterruptedException e) {
                e.printStackTrace();
            }
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
                          VirtualPath currentDirectory,
                          Permissions permissions, Links links,
                          Slave.Listener listener) throws IOException {
        Pipe slave2hub = Pipe.open();
        Pipe hub2slave = Pipe.open();

        Slave slave = new Slave(this, process,
                                new SyscallReadableChannel(hub2slave.source()),
                                new SyscallWritableChannel(slave2hub.sink()),
                                currentDirectory, permissions, links, listener);
        process.add(slave);

        mSlaveHub.addSlave(new SyscallReadableChannel(slave2hub.source()),
                           new SyscallWritableChannel(hub2slave.sink()),
                           newPairId);

        return slave;
    }

    /**
     * This is for fork(2).
     */
    public Slave newProcess(PairId pairId, Process parent,
                            VirtualPath currentDirectory,
                            Permissions permissions, Links links,
                            Slave.Listener listener) throws IOException {
        Pid pid = mPidGenerator.next();
        Process process = new Process(pid, parent, parent.dupFileTable());
        parent.addChild(process);
        addProcess(process);
        return newSlave(pairId, process, currentDirectory, permissions, links,
                        listener);
    }

    public int run(SyscallReadableChannel in, SyscallWritableChannel out,
                   VirtualPath currentDirectory, InputStream stdin,
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

        Pipe slave2hub = Pipe.open();
        Pipe hub2slave = Pipe.open();
        Slave slave = new Slave(
                this, process,
                new SyscallReadableChannel(hub2slave.source()),
                new SyscallWritableChannel(slave2hub.sink()),
                currentDirectory, stdin, stdout, stderr,
                permissions, links, listener);
        process.add(slave);

        mSlaveHub = new SlaveHub(this, in, out,
                                 new SyscallReadableChannel(slave2hub.source()),
                                 new SyscallWritableChannel(hub2slave.sink()));
        synchronized (this) {
            notifyAll();
        }

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
        try {
            synchronized (this) {
                while (!isCancellable()) {
                    wait();
                }
                mCancelled = true;
                for (Process process: mProcesses) {
                    process.terminate();
                }
            }
        }
        catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public Alarm getAlarm() {
        return mAlarm;
    }

    /**
     * Binds a Unix domain socket to a path. This method handles a socket as an
     * Object instance, because I dislike disclosing the Slave.Socket class.
     */
    public void bindSocket(PhysicalPath path, Object socket) throws UnixException {
        mLocalBoundSockets.bind(path, socket);
    }

    /**
     * Returns a socket bound to a given path. This method returns an Object.
     * Callers have responsibility to cast it to Slave.Socket.
     */
    public Object getUnixDomainSocket(PhysicalPath path) throws UnixException {
        return mLocalBoundSockets.get(path);
    }

    public void unlinkUnixDomainNode(PhysicalPath path) throws UnixException {
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

    private boolean isCancellable() {
        return mSlaveHub != null;
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
        out.println("usage: Main port currentDirectory");
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

    public static void main(String[] args) {
        Logging.Destination destination;
        try {
            destination = new Logging.FileDestination("fsyscall.log");
        }
        catch (IOException e) {
            e.printStackTrace();
            System.exit(254);
            return; // This is needed to avoid the unreachable warning.
        }
        Logging.setDestination(destination);
        mLogger.info("================================");

        int port;
        try {
            port = Integer.parseInt(args[0]);
        }
        catch (ArrayIndexOutOfBoundsException unused) {
            Application.usage(System.out);
            System.exit(253);
            return;
        }
        catch (NumberFormatException unused) {
            Application.usage(System.out);
            System.exit(252);
            return;
        }
        SocketAddress address = new InetSocketAddress("127.0.0.1", port);
        SocketChannel socket;
        try {
            socket = SocketChannel.open(address);
            socket.socket().setTcpNoDelay(true);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.exit(251);
            return;
        }

        MainCleanUp cleanUp;
        SyscallReadableChannel readableChannel;
        SyscallWritableChannel writableChannel;
        String key = "fsyscall.ssl";
        String ssl = System.getProperty(key, "false");
        if (ssl.equals("true")) {
            String keyStore = System.getProperty("fsyscall.keystore");
            String password = System.getProperty("fsyscall.keystore_password");
            SSLContext context;
            try {
                context = SSLUtil.createContext(keyStore, password);
            }
            catch (IOException e) {
                e.printStackTrace();
                System.exit(246);
                return;
            }
            catch (GeneralSecurityException e) {
                e.printStackTrace();
                System.exit(245);
                return;
            }
            Pipe front2back;
            Pipe back2front;
            SSLFrontEnd sslFrontEnd;
            try {
                front2back = Pipe.open();
                back2front = Pipe.open();
                sslFrontEnd = new SSLFrontEnd(context, socket,
                                              back2front.source(),
                                              front2back.sink());
                Pipe.SourceChannel source = front2back.source();
                readableChannel = new SyscallReadableChannel(source);
                writableChannel = new SyscallWritableChannel(back2front.sink());
            }
            catch (IOException e) {
                e.printStackTrace();
                System.exit(244);
                return;
            }
            cleanUp = new SSLMainCleanUp(sslFrontEnd);
        }
        else if (ssl.equals("false")) {
            try {
                readableChannel = new SyscallReadableChannel(socket);
            }
            catch (IOException e) {
                e.printStackTrace();
                System.exit(247);
                return;
            }
            writableChannel = new SyscallWritableChannel(socket);
            cleanUp = new NopMainCleanUp();
        }
        else {
            System.err.format("%s must be true or false, %s is not allowed",
                              key, ssl);
            System.exit(248);
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
            System.exit(250);
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
                exitStatus = app.run(readableChannel, writableChannel,
                                     new VirtualPath(args[1]), stdin, stdout,
                                     stderr, perm, links, null, resourceDir);
            }
            catch (Throwable e) {
                e.printStackTrace();
                exitStatus = 249;
            }
        }
        finally {
            cleanUp.run();
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
