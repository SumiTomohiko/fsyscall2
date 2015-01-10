package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.TimeZone;

/*
 * Android 3.2.1 does not have UnixSystem.
 */
//import com.sun.security.auth.module.UnixSystem;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;
import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.PollFd;
import jp.gr.java_conf.neko_daisuki.fsyscall.PollFds;
import jp.gr.java_conf.neko_daisuki.fsyscall.Sigaction;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.SignalSet;
import jp.gr.java_conf.neko_daisuki.fsyscall.SocketAddress;
import jp.gr.java_conf.neko_daisuki.fsyscall.SyscallResult;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixDomainAddress;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallInputStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallOutputStream;

/**
 * The class for fsyscall process.
 *
 * The Slave class must be public because the NexecClient is using the
 * Slave.Listener.
 */
public class Slave implements Runnable {

    public interface Listener {

        public static class NopListener implements Listener {

            public SocketCore onConnect(int domain, int type, int protocol,
                                        SocketAddress addr) {
                return null;
            }
        }

        public static final Listener NOP = new NopListener();

        public SocketCore onConnect(int domain, int type, int protocol,
                                    SocketAddress addr);
    }

    private enum State {
        NORMAL,
        ZOMBIE
    }

    private static class GetSocketException extends Exception {

        private Errno mErrno;

        public GetSocketException(Errno errno) {
            mErrno = errno;
        }

        public Errno getErrno() {
            return mErrno;
        }
    }

    private abstract static interface SelectPred {

        public boolean isReady(UnixFile file) throws UnixException;
    }

    private static class WriteSelectPred implements SelectPred {

        public boolean isReady(UnixFile file) throws UnixException {
            return file.isReadyToWrite();
        }
    }

    private static class ReadSelectPred implements SelectPred {

        public boolean isReady(UnixFile file) throws UnixException {
            return file.isReadyToRead();
        }
    }

    private static interface TimeoutDetector {

        public boolean isTimeout(long usec);
    }

    private static class ZeroTimeoutDetector implements TimeoutDetector {

        private int mCount = 0;

        public boolean isTimeout(long usec) {
            boolean timeouted = 0 < mCount;
            mCount++;
            return timeouted;
        }
    }

    private static class InfinityTimeoutDetector implements TimeoutDetector {

        public boolean isTimeout(long usec) {
            return false;
        }
    }

    private static class TrueTimeoutDetector implements TimeoutDetector {

        private long mTime; // usec

        public TrueTimeoutDetector(Unix.TimeVal timeout) {
            mTime = 1000000 * timeout.tv_sec + timeout.tv_usec;
        }

        public TrueTimeoutDetector(long msec) {
            mTime = 1000 * msec;
        }

        public boolean isTimeout(long usec) {
            return mTime <= usec;
        }
    }

    private class Socket extends UnixFile {

        private class PipeCore implements SocketCore {

            private InputStream mIn;
            private OutputStream mOut;

            public PipeCore(Pair pair) {
                mIn = pair.getInputStream();
                mOut = pair.getOutputStream();
            }

            @Override
            public InputStream getInputStream() {
                return mIn;
            }

            @Override
            public OutputStream getOutputStream() {
                return mOut;
            }

            @Override
            public void close() throws IOException {
                mIn.close();
                mOut.close();
            }
        }

        private class LocalBoundCore implements SocketCore {

            private String mPath;

            public LocalBoundCore(String path) {
                mPath = path;
            }

            public String getPath() {
                return mPath;
            }

            @Override
            public InputStream getInputStream() {
                return null;
            }

            @Override
            public OutputStream getOutputStream() {
                return null;
            }

            @Override
            public void close() throws IOException {
                mConnectingRequests = null;
                setCore(null);
            }
        }

        private class ConnectingRequest {

            private Socket mPeer;
            private Pair mPair;

            public ConnectingRequest(Socket peer) {
                mPeer = peer;
            }

            public Socket getPeer() {
                return mPeer;
            }

            public void setPair(Pair pair) {
                mPair = pair;
            }

            public Pair getPair() {
                return mPair;
            }

            public boolean isAccepted() {
                return mPair != null;
            }
        }

        private int mDomain;
        private int mType;
        private int mProtocol;
        private SocketAddress mName;
        private Socket mPeer;

        private SocketCore mCore;
        private Queue<ConnectingRequest> mConnectingRequests;

        public Socket(int domain, int type, int protocol) {
            mDomain = domain;
            mType = type;
            mProtocol = protocol;
        }

        public Socket(int domain, int type, int protocol, SocketAddress name,
                      Socket peer) {
            this(domain, type, protocol);
            mName = name;
            setPeer(peer);
        }

        public Socket getPeer() {
            return mPeer;
        }

        public void setPeer(Socket peer) {
            mPeer = peer;
        }

        public int getDomain() {
            return mDomain;
        }

        public int getType() {
            return mType;
        }

        public int getProtocol() {
            return mProtocol;
        }

        public SocketAddress getName() {
            return mName;
        }

        public void setCore(SocketCore core) {
            mCore = core;
        }

        public boolean isReadyToRead() throws UnixException {
            try {
                return 0 < mCore.getInputStream().available();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        public boolean isReadyToWrite() throws UnixException {
            return true;
        }

        public int read(byte[] buffer) throws UnixException {
            if (isNonBlocking() && !isReadyToRead()) {
                throw new UnixException(Errno.EAGAIN);
            }
            try {
                return mCore.getInputStream().read(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            int len = buffer.length;
            try {
                return mCore.getInputStream().read(buffer, (int)offset, len);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        public int write(byte[] buffer) throws UnixException {
            try {
                mCore.getOutputStream().write(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return buffer.length;
        }

        public long lseek(long offset, int whence) throws UnixException {
            return offset;
        }

        public Unix.Stat fstat() throws UnixException {
            throw new UnixException(Errno.ENOSYS);
        }

        public void connect(UnixDomainAddress addr) throws UnixException {
            String path = addr.getPath();
            Socket peer = (Socket)mApplication.getUnixDomainSocket(path);
            mName = new UnixDomainAddress(2, addr.getFamily(), "");
            connect(peer);
        }

        public void connect(Socket peer) throws UnixException {
            Queue<ConnectingRequest> queue = peer.mConnectingRequests;
            if (queue == null) {
                throw new UnixException(Errno.EINVAL);
            }
            ConnectingRequest request = new ConnectingRequest(this);
            synchronized (queue) {
                queue.offer(request);
                queue.notifyAll();
            }
            synchronized (request) {
                while (!request.isAccepted()) {
                    try {
                        request.wait();
                    }
                    catch (InterruptedException e) {
                        throw new UnixException(Errno.EINTR);
                    }
                }
            }
            setCore(new PipeCore(request.getPair()));

            // The accepting side sets mPeer of this socket.
        }

        public void bind(UnixDomainAddress addr) throws UnixException {
            if (mName != null) {
                throw new UnixException(Errno.EINVAL);
            }
            mConnectingRequests = new LinkedList<ConnectingRequest>();
            String path = addr.getPath();
            mApplication.bindSocket(path, this);
            setCore(new LocalBoundCore(path));
            mName = addr;
        }

        public Socket accept() throws UnixException {
            if (mConnectingRequests == null) {
                throw new UnixException(Errno.EINVAL);
            }
            ConnectingRequest request;
            synchronized (mConnectingRequests) {
                while (mConnectingRequests.isEmpty()) {
                    try {
                        mConnectingRequests.wait();
                    }
                    catch (InterruptedException e) {
                        throw new UnixException(Errno.EINTR, e);
                    }
                }
                request = mConnectingRequests.remove();
            }

            Pipe s2c;
            Pipe c2s;
            try {
                s2c = new Pipe();
                c2s = new Pipe();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            InputStream in = s2c.getInputStream();
            OutputStream out = c2s.getOutputStream();
            Pair clientPair = new Pair(in, out);
            request.setPair(clientPair);
            Socket peer = request.getPeer();
            peer.setPeer(this);
            synchronized (request) {
                request.notifyAll();
            }

            Socket socket = new Socket(mDomain, mType, mProtocol, mName, peer);
            Pair pair = new Pair(c2s.getInputStream(), s2c.getOutputStream());
            socket.setCore(new PipeCore(pair));

            return socket;
        }

        public void listen(int backlog) throws UnixException {
            // does nothing.
        }

        protected void doClose() throws UnixException {
            try {
                mCore.close();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }
    }

    private class ExternalPeer extends Socket {

        public ExternalPeer(int domain, int type, int protocol, SocketAddress name, Socket peer) {
            super(domain, type, protocol, name, peer);
        }
    }

    private abstract static class UnixRandomAccessFile extends UnixFile {

        protected RandomAccessFile mFile;

        protected UnixRandomAccessFile(String path, String mode) throws UnixException {
            try {
                mFile = new RandomAccessFile(path, mode);
            }
            catch (FileNotFoundException e) {
                throw new UnixException(Errno.ENOENT, e);
            }
            catch (SecurityException e) {
                throw new UnixException(Errno.EPERM, e);
            }
        }

        public Unix.Stat fstat() throws UnixException {
            Unix.Stat st = new Unix.Stat();

            try {
                st.st_size = mFile.length();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }

            return st;
        }

        public long lseek(long offset, int whence) throws UnixException {
            long pos;
            switch (whence) {
            case Unix.Constants.SEEK_SET:
                pos = offset;
                break;
            case Unix.Constants.SEEK_CUR:
                try {
                    pos = mFile.getFilePointer() + offset;
                }
                catch (IOException e) {
                    throw new UnixException(Errno.EIO);
                }
                break;
            case Unix.Constants.SEEK_END:
                try {
                    pos = mFile.length() + offset;
                }
                catch (IOException e) {
                    throw new UnixException(Errno.EIO);
                }
                break;
            case Unix.Constants.SEEK_DATA:
            case Unix.Constants.SEEK_HOLE:
            default:
                throw new UnixException(Errno.EINVAL);
            }

            try {
                mFile.seek(pos);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }

            return pos;
        }

        protected void doClose() throws UnixException {
            try {
                mFile.close();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EBADF, e);
            }
        }
    }

    private static class UnixInputFile extends UnixRandomAccessFile {

        public UnixInputFile(String path) throws UnixException {
            super(path, "r");
        }

        public boolean isReadyToRead() throws UnixException {
            try {
                return mFile.getFilePointer() < mFile.length();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        public boolean isReadyToWrite() throws UnixException {
            return false;
        }

        public int read(byte[] buffer) throws UnixException {
            int nBytes;
            try {
                nBytes = mFile.read(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return nBytes != -1 ? nBytes : 0;
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            int nBytes;
            try {
                long initialPosition = mFile.getFilePointer();
                mFile.seek(offset);
                try {
                    nBytes = mFile.read(buffer);
                }
                finally {
                    mFile.seek(initialPosition);
                }
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return nBytes == -1 ? 0 : nBytes;
        }

        public int write(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }
    }

    private static class UnixOutputFile extends UnixRandomAccessFile {

        public UnixOutputFile(String path) throws UnixException {
            super(path, "rw");
        }

        public boolean isReadyToRead() throws UnixException {
            return false;
        }

        public boolean isReadyToWrite() throws UnixException {
            return true;
        }

        public int read(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }

        public int write(byte[] buffer) throws UnixException {
            try {
                mFile.write(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return buffer.length;
        }
    }

    private abstract static class UnixStream extends UnixFile {

        public long lseek(long offset, int whence) throws UnixException {
            throw new UnixException(Errno.ESPIPE);
        }

        public Unix.Stat fstat() throws UnixException {
            throw new UnixException(Errno.ESPIPE);
        }
    }

    private static class UnixInputStream extends UnixStream {

        private InputStream mIn;

        public UnixInputStream(InputStream in) {
            mIn = in;
        }

        public boolean isReadyToRead() throws UnixException {
            try {
                return 0 < mIn.available();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        public boolean isReadyToWrite() throws UnixException {
            return false;
        }

        public int read(byte[] buffer) throws UnixException {
            int nBytes;
            try {
                nBytes = mIn.read(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return nBytes != -1 ? nBytes : 0;
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            throw new UnixException(Errno.ESPIPE);
        }

        public int write(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }

        protected void doClose() throws UnixException {
            try {
                mIn.close();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EBADF, e);
            }
        }
    }

    private static class UnixOutputStream extends UnixStream {

        private OutputStream mOut;

        public UnixOutputStream(OutputStream out) {
            mOut = out;
        }

        public boolean isReadyToRead() throws UnixException {
            return false;
        }

        public boolean isReadyToWrite() throws UnixException {
            return true;
        }

        public int read(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            throw new UnixException(Errno.ESPIPE);
        }

        public int write(byte[] buffer) throws UnixException {
            try {
                mOut.write(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return buffer.length;
        }

        protected void doClose() throws UnixException {
            try {
                mOut.close();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EBADF, e);
            }
        }
    }

    private interface FcntlProc {

        public static class Nop implements FcntlProc {

            public void run(SyscallResult.Generic32 result, UnixFile file,
                            int fd, int cmd, long arg) {
                result.retval = 0;
            }
        }

        public static final FcntlProc NOP = new Nop();

        public void run(SyscallResult.Generic32 result, UnixFile file, int fd,
                        int cmd, long arg);
    }

    private static class FcntlProcs {

        private Map<Integer, FcntlProc> mProcs;

        public FcntlProcs() {
            mProcs = new HashMap<Integer, FcntlProc>();
        }

        public void put(int cmd, FcntlProc proc) {
            mProcs.put(Integer.valueOf(cmd), proc);
        }

        public void run(SyscallResult.Generic32 result, UnixFile file, int fd,
                        int cmd, long arg) {
            FcntlProc proc = mProcs.get(Integer.valueOf(cmd));
            FcntlProc f = proc != null ? proc : FcntlProc.NOP;
            f.run(result, file, fd, cmd, arg);
        }
    }

    private class FSetFlProc implements FcntlProc {

        public void run(SyscallResult.Generic32 result, UnixFile file, int fd,
                        int cmd, long arg) {
            file.enableNonBlocking((Unix.Constants.O_NONBLOCK & arg) != 0);
        }
    }

    private class FGetFdProc implements FcntlProc {

        public void run(SyscallResult.Generic32 result, UnixFile file, int fd,
                        int cmd, long arg) {
            boolean closeOnExec = file.getCloseOnExec();
            result.retval = closeOnExec ? Unix.Constants.FD_CLOEXEC : 0;
        }
    }

    private class FSetFdProc implements FcntlProc {

        public void run(SyscallResult.Generic32 result, UnixFile file, int fd,
                        int cmd, long arg) {
            file.setCloseOnExec(arg == Unix.Constants.FD_CLOEXEC);
            result.retval = 0;
        }
    }

    private static final int UID = 1001;
    private static final int UNIX_FILE_NUM = 256;

    private static Map<Integer, String> mFcntlCommands;
    private static Logging.Logger mLogger;

    private Application mApplication;
    private SyscallInputStream mIn;
    private SyscallOutputStream mOut;
    private Permissions mPermissions;
    private Links mLinks;
    private Listener mListener;

    private Pid mPid;
    private State mState = State.NORMAL;
    private UnixFile[] mFiles;
    private SignalSet mPendingSignals = new SignalSet();
    private SignalSet mActiveSignals;
    private Integer mExitStatus;

    private SlaveHelper mHelper;
    private FcntlProcs mFcntlProcs;
    private boolean mCancelled = false;

    public Slave(Application application, Pid pid, InputStream hubIn,
                 OutputStream hubOut, InputStream stdin, OutputStream stdout,
                 OutputStream stderr, Permissions permissions, Links links,
                 Listener listener) throws IOException {
        mLogger.info("a slave is starting.");

        UnixFile[] files = new UnixFile[UNIX_FILE_NUM];
        files[0] = new UnixInputStream(stdin);
        files[1] = new UnixOutputStream(stdout);
        files[2] = new UnixOutputStream(stderr);

        initialize(application, pid, hubIn, hubOut, files, permissions, links,
                   listener, new SignalSet());

        writeOpenedFileDescriptors();
        mLogger.verbose("file descripters were transfered from the slave.");
    }

    /**
     * Constructor for fork(2).
     */
    public Slave(Application application, Pid pid, InputStream hubIn,
                 OutputStream hubOut, UnixFile[] files, Permissions permissions,
                 Links links, Listener listener, SignalSet activeSignals) {
        initialize(application, pid, hubIn, hubOut, files, permissions, links,
                   listener, activeSignals.clone());
    }

    public void kill(Signal sig) throws UnixException {
        if (sig == null) {
            throw new UnixException(Errno.EINVAL);
        }
        if (!mActiveSignals.contains(sig)) {
            return;
        }
        mPendingSignals.add(sig);
    }

    public Integer getExitStatus() {
        return mExitStatus;
    }

    @Override
    public void run() {
        String name = Thread.currentThread().getName();
        mLogger.info(String.format("a slave started: %s", name));

        try {
            try {
                try {
                    while (!mCancelled && (mExitStatus == null)) {
                        for (Signal sig: mPendingSignals.toCollection()) {
                            writeSignaled(sig);
                        }
                        if (mIn.isReady()) {
                            mHelper.runSlave();
                        }

                        try {
                            Thread.sleep(10 /* msec */);
                        }
                        catch (InterruptedException _) {
                            mCancelled = true;
                        }
                    }
                }
                finally {
                    mIn.close();
                }
            }
            finally {
                mOut.close();
            }
        }
        catch (IOException e) {
            mLogger.err("I/O error", e);
            e.printStackTrace();
        }
        mState = State.ZOMBIE;
        mApplication.onSlaveTerminated(this);
    }

    public void cancel() {
        mCancelled = true;
    }

    public Pid getPid() {
        return mPid;
    }

    public boolean isReady() throws IOException {
        return mIn.isReady();
    }

    public boolean isZombie() {
        return mState == State.ZOMBIE;
    }

    public SyscallResult.Generic32 doSigaction(int sig, Sigaction act) throws IOException {
        String fmt = "sigaction(sig=%d (%s), act=%s)";
        mLogger.info(String.format(fmt, sig, Signal.toString(sig), act));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        Signal signal;
        try {
            signal = Signal.valueOf(sig);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        if (act.sa_handler == Sigaction.Handler.ACTIVE) {
            mActiveSignals.add(signal);
        }
        else {
            mActiveSignals.remove(signal);
        }

        return result;
    }

    public SyscallResult.Generic32 doKill(int pid, int signum) throws IOException {
        String fmt = "kill(pid=%d, signum=%d (%s))";
        mLogger.info(String.format(fmt, pid, signum, Signal.toString(signum)));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        try {
            mApplication.kill(new Pid(pid), Signal.valueOf(signum));
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doListen(int s, int backlog) throws IOException {
        mLogger.info(String.format("listen(s=%d, backlog=%d)", s, backlog));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        Socket sock;
        try {
            sock = getSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            sock.listen(backlog);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doOpen(String path, int flags, int mode) throws IOException {
        String fmt = "open(path=%s, flags=%d, mode=%d)";
        mLogger.info(String.format(fmt, path, flags, mode));

        return openActualFile(mLinks.get(path), flags, mode);
    }

    public SyscallResult.Read doRead(int fd, long nbytes) throws IOException {
        mLogger.info(String.format("read(fd=%d, nbytes=%d)", fd, nbytes));

        SyscallResult.Read result = new SyscallResult.Read();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        /*
         * This implementation cannot handle the nbytes parameter which is
         * greater than maximum value of int (2^30 - 1).
         */
        byte[] buffer = new byte[(int)nbytes];
        try {
            result.retval = file.read(buffer);
        }
        catch (UnixException e) {
            result.retval = -1;
            result.errno = e.getErrno();
            return result;
        }

        result.buf = Arrays.copyOf(buffer, (int)result.retval);
        return result;
    }

    public SyscallResult.Generic64 doLseek(int fd, long offset, int whence) throws IOException {
        String fmt = "lseek(fd=%d, offset=%d, whence=%d)";
        mLogger.info(String.format(fmt, fd, offset, whence));

        SyscallResult.Generic64 result = new SyscallResult.Generic64();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        long pos;
        try {
            pos = file.lseek(offset, whence);
        }
        catch (UnixException e) {
            result.retval =-1;
            result.errno = e.getErrno();
            return result;
        }

        result.retval = pos;
        return result;
    }

    public SyscallResult.Pread doPread(int fd, long nbyte, long offset) throws IOException {
        String fmt = "pread(fd=%d, nbyte=%d, offset=%d)";
        mLogger.info(String.format(fmt, fd, nbyte, offset));

        SyscallResult.Pread result = new SyscallResult.Pread();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        byte[] buffer = new byte[(int)nbyte];
        try {
            result.retval = file.pread(buffer, offset);
        }
        catch (UnixException e) {
            result.retval = -1;
            result.errno = e.getErrno();
            return result;
        }

        result.buf = Arrays.copyOf(buffer, (int)result.retval);
        return result;
    }

    public SyscallResult.Accept doGetpeername(int s, int namelen) throws IOException {
        String fmt = "getpeername(s=%d, namelen=%d)";
        mLogger.info(String.format(fmt, s, namelen));
        SyscallResult.Accept result = new SyscallResult.Accept();

        Socket socket;
        try {
            socket = getSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }

        SocketAddress addr = socket.getPeer().getName();
        result.addr = addr;
        result.addrlen = addr.length();

        return result;
    }

    public SyscallResult.Accept doGetsockname(int s, int namelen) throws IOException {
        String fmt = "getsockname(s=%d, namelen=%d)";
        mLogger.info(String.format(fmt, s, namelen));
        SyscallResult.Accept result = new SyscallResult.Accept();

        Socket socket;
        try {
            socket = getSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }

        SocketAddress addr = socket.getName();
        result.addr = addr;
        result.addrlen = addr.length();

        return result;
    }

    public SyscallResult.Accept doAccept(int s, int addrlen) throws IOException {
        mLogger.info(String.format("accept(s=%d, addrlen=%d)", s, addrlen));
        SyscallResult.Accept result = new SyscallResult.Accept();

        Socket socket;
        try {
            socket = getSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }

        Socket clientSocket;
        int fd;
        try {
            clientSocket = socket.accept();
            fd = registerFile(clientSocket);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        SocketAddress addr = clientSocket.getPeer().getName();
        result.retval = fd;
        result.addr = addr;
        result.addrlen = addr.length();

        return result;
    }

    /**
     * System call handler for issetugid(2). This always returns zero.
     */
    public SyscallResult.Generic32 doIssetugid() throws IOException {
        mLogger.info("doIssetugid()");

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = 0;
        return result;
    }

    /**
     * Runs lstat(2). This lstat(2) behaves as same as stat(2) (This
     * implementation does not return the information of the link itself).
     * Because Java 1.6 does not handle symbolic links (Java 1.7 can do with the
     * java.nio.files package).
     */
    public SyscallResult.Lstat doLstat(String path) throws IOException {
        mLogger.info(String.format("lstat(path=%s)", path));

        SyscallResult.Lstat result = new SyscallResult.Lstat();

        SyscallResult.Stat statResult = doStat(path);
        result.retval = statResult.retval;
        result.errno = statResult.errno;
        result.ub = statResult.ub;

        return result;
    }

    public SyscallResult.Fstat doFstat(int fd) throws IOException {
        mLogger.info(String.format("fstat(fd=%d)", fd));

        SyscallResult.Fstat result = new SyscallResult.Fstat();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
            result.sb = file.fstat();
        }
        catch (UnixException e) {
            result.retval = -1;
            result.errno = e.getErrno();
            return result;
        }

        result.retval = 0;
        return result;
    }

    public SyscallResult.Stat doStat(String path) throws IOException {
        mLogger.info(String.format("stat(path=%s)", path));

        return statActualFile(mLinks.get(path));
    }

    public SyscallResult.Generic32 doBind(int s, UnixDomainAddress addr,
                                          int addrlen) throws IOException {
        String fmt = "bind(s=%d, addr=%s, addrlen=%d)";
        mLogger.info(String.format(fmt, s, addr, addrlen));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        Socket sock;
        try {
            sock = getSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            sock.bind(addr);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doConnect(int s, UnixDomainAddress name,
                                             int namelen) throws IOException {
        String fmt = "connect(s=%d, name=%s, namelen=%d)";
        mLogger.info(String.format(fmt, s, name, namelen));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        Socket sock;
        try {
            sock = getSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        Errno err = Errno.ENOSYS;
        try {
            sock.connect(name);
            return result;
        }
        catch (UnixException e) {
            err = e.getErrno();
        }

        int domain = sock.getDomain();
        int type = sock.getType();
        int protocol = sock.getProtocol();
        SocketCore core = mListener.onConnect(domain, type, protocol, name);
        if (core == null) {
            result.setError(err);
            return result;
        }
        sock.setCore(core);
        Socket peer = new ExternalPeer(domain, type, protocol, name, sock);
        sock.setPeer(peer);
        result.retval = 0;

        return result;
    }

    public SyscallResult.Generic32 doWritev(int fd, Unix.IoVec[] iovec) throws IOException {
        mLogger.info(String.format("writev(fd=%d, iovec)", fd));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        int nBytes = 0;
        for (Unix.IoVec v: iovec) {
            nBytes += v.iov_base.length;
        }
        byte[] buffer = new byte[nBytes];
        int pos = 0;
        for (Unix.IoVec v: iovec) {
            int len = v.iov_base.length;
            System.arraycopy(v.iov_base, 0, buffer, pos, len);
            pos += len;
        }

        try {
            result.retval = file.write(buffer);
        }
        catch (UnixException e) {
            result.retval = -1;
            result.errno = e.getErrno();
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doSocket(int domain, int type, int protocol) throws IOException {
        String fmt = "socket(domain=%d, type=%d, protocol=%d)";
        mLogger.info(String.format(fmt, domain, type, protocol));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        UnixFile file = new Socket(domain, type, protocol);
        file.acquire();
        int fd;
        try {
            fd = registerFile(file);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        result.retval = fd;

        return result;
    }

    public SyscallResult.Generic32 doPoll(PollFds fds, int nfds, int timeout) throws IOException {
        String fmt = "poll(fds=%s, nfds=%d, timeout=%d)";
        mLogger.info(String.format(fmt, fds, nfds, timeout));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        TimeoutDetector timeoutDetector;
        switch (timeout) {
        case Unix.Constants.INFTIM:
            timeoutDetector = new InfinityTimeoutDetector();
            break;
        case 0:
            timeoutDetector = new ZeroTimeoutDetector();
            break;
        default:
            timeoutDetector = new TrueTimeoutDetector(timeout);
            break;
        }

        long usecInterval = 100 * 1000;
        long usecTime = 0;
        while (!timeoutDetector.isTimeout(usecTime) && !mCancelled) {
            for (PollFd fd: fds) {
                try {
                    UnixFile file = getValidFile(fd.getFd());
                    int events = fd.getEvents();
                    if ((events & Unix.Constants.POLLIN) != 0) {
                        if (file.isReadyToRead()) {
                            fd.addRevents(Unix.Constants.POLLIN);
                        }
                    }
                    if ((events & Unix.Constants.POLLOUT) != 0) {
                        if (file.isReadyToWrite()) {
                            fd.addRevents(Unix.Constants.POLLOUT);
                        }
                    }
                }
                catch (UnixException e) {
                    result.retval = -1;
                    result.errno = e.getErrno();
                    return result;
                }
            }
            int nReadyFds = 0;
            for (PollFd fd: fds) {
                nReadyFds += (fd.getRevents() != 0 ? 1 : 0);
            }
            if (0 < nReadyFds) {
                result.retval = nReadyFds;
                break;
            }

            try {
                Thread.sleep(usecInterval / 1000);
            }
            catch (InterruptedException e) {
                result.retval = -1;
                result.errno = Errno.EINTR;
                return result;
            }
            usecTime += usecInterval;
        }

        return result;
    }

    public SyscallResult.Select doSelect(int nfds, Collection<Integer> in, Collection<Integer> ou, Collection<Integer> ex, Unix.TimeVal timeout) throws IOException {
        String fmt = "select(nfds=%d, in, ou, ex, timeout)";
        mLogger.info(String.format(fmt, nfds));

        SyscallResult.Select result = new SyscallResult.Select();

        TimeoutDetector timeoutDetector = timeout != null ? new TrueTimeoutDetector(timeout) : new InfinityTimeoutDetector();

        long usecInterval = 100 * 1000;

        Collection<Integer> inReady = new HashSet<Integer>();
        Collection<Integer> ouReady = new HashSet<Integer>();
        Collection<Integer> exReady = new HashSet<Integer>();
        long usecTime = 0;
        int nReadyFds = 0;
        SelectPred readPred = new ReadSelectPred();
        SelectPred writePred = new WriteSelectPred();
        while (!timeoutDetector.isTimeout(usecTime) && (nReadyFds == 0) && !mCancelled) {
            inReady.clear();
            ouReady.clear();
            exReady.clear();

            try {
                selectFds(inReady, in, readPred);
                selectFds(ouReady, ou, writePred);
                // TODO: Perform for ex (But how?).
            }
            catch (UnixException e) {
                result.retval = -1;
                result.errno = e.getErrno();
                return result;
            }

            try {
                Thread.sleep(usecInterval / 1000);
            }
            catch (InterruptedException e) {
                result.retval = -1;
                result.errno = Errno.EINTR;
                return result;
            }
            usecTime += usecInterval;

            nReadyFds = inReady.size() + ouReady.size() + exReady.size();
        }

        result.retval = nReadyFds;
        if (nReadyFds == 0) {
            return result;
        }

        result.in = inReady;
        result.ou = ouReady;
        result.ex = exReady;
        return result;
    }

    /**
     * readlink(2) implementation. This returns always EINVAL. Because Java 1.6
     * cannot handle symbolic links.
     */
    public SyscallResult.Readlink doReadlink(String path, long count) throws IOException {
        String fmt = "readlink(path=%s, count=%d)";
        mLogger.info(String.format(fmt, path, count));

        return readlinkActualFile(mLinks.get(path), count);
    }

    /**
     * The dummy implementation of access(2).
     */
    public SyscallResult.Generic32 doAccess(String path, int flags) throws IOException {
        String fmt = "access(path=%s, flags=0x%02x)";
        mLogger.info(String.format(fmt, path, flags));

        return accessActualFile(mLinks.get(path), flags);
    }

    public SyscallResult.Generic32 doLink(String path1, String path2) throws IOException {
        mLogger.info(String.format("link(path1=%s, path2=%s)", path1, path2));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = -1;
        result.errno = Errno.ENOSYS;
        return result;
    }

    public SyscallResult.Gettimeofday doGettimeofday() throws IOException {
        mLogger.info("gettimeofday(tp, tzp)");

        long millis = System.currentTimeMillis();
        long sec = millis / 1000;
        long usec = (millis % 1000) * 1000;
        Unix.TimeVal tv = new Unix.TimeVal(sec, usec);
        int minuteswest = TimeZone.getDefault().getRawOffset() / 1000 / 60;
        Unix.TimeZone tz = new Unix.TimeZone(minuteswest, 0);

        SyscallResult.Gettimeofday result = new SyscallResult.Gettimeofday();
        result.tp = tv;
        result.tzp = tz;
        result.retval = 0;

        return result;
    }

    public SyscallResult.Generic32 doFcntl(int fd, int cmd, long arg) throws IOException {
        String fmt = "fcntl(fd=%d, cmd=%d (%s), arg=%d%s)";
        String name = mFcntlCommands.get(cmd);
        String s = makeFcntlArgString(cmd, arg);
        mLogger.info(String.format(fmt, fd, cmd, name, arg, s));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        mFcntlProcs.run(result, file, fd, cmd, arg);

        return result;
    }

    public SyscallResult.Generic32 doDup(long oldd) throws IOException {
        mLogger.info(String.format("dup(oldd=%d)", oldd));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        int d = (int)oldd;
        UnixFile file = getFile(d);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        file.acquire();
        int newfd;
        try {
            newfd = registerFile(file);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        result.retval = newfd;

        return result;
    }

    public SyscallResult.Generic32 doClose(int fd) throws IOException {
        mLogger.info(String.format("close(fd=%d)", fd));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
            file.close();
        }
        catch (UnixException e) {
            result.retval = -1;
            result.errno = e.getErrno();
            return result;
        }

        mFiles[fd] = null;

        result.retval = 0;
        return result;
    }

    /**
     * Fake implementation of getpid(2). Java does not have any compatible ways
     * to getpid(2). So this method returns the dummy value.
     */
    public SyscallResult.Generic32 doGetpid() throws IOException {
        mLogger.info("getpid()");
        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = mPid.toInteger();
        return result;
    }

    public SyscallResult.Generic32 doGeteuid() throws IOException {
        mLogger.info("geteuid()");
        return doGetuid();
    }

    public SyscallResult.Generic32 doGetegid() throws IOException {
        mLogger.info("getegid()");
        return doGetgid();
    }

    public SyscallResult.Generic32 doGetgid() throws IOException {
        mLogger.info("getgid()");
        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        //result.retval = (int)(new UnixSystem().getGid());
        result.retval = 1001;
        return result;
    }

    public SyscallResult.Getresuid doGetresuid() throws IOException {
        mLogger.info("getresuid(*ruid, *euid, *suid)");
        SyscallResult.Getresuid result = new SyscallResult.Getresuid();
        result.ruid = result.euid = result.suid = UID;
        result.retval = 0;
        return result;
    }

    public SyscallResult.Generic32 doGetuid() throws IOException {
        mLogger.info("getuid()");
        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        //result.retval = (int)(new UnixSystem().getUid());
        result.retval = UID;
        return result;
    }

    public SyscallResult.Generic64 doWrite(int fd, byte[] buf, long nbytes) throws IOException {
        mLogger.info(String.format("write(fd=%d, buf, nbytes=%d)", fd, nbytes));

        SyscallResult.Generic64 result = new SyscallResult.Generic64();

        UnixFile file = getFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
            result.retval = file.write(buf);
        }
        catch (UnixException e) {
            result.retval = -1;
            result.errno = e.getErrno();
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doFork(PairId pairId) throws IOException {
        mLogger.info(String.format("fork(pairId=%s)", pairId.toString()));

        int len = mFiles.length;
        UnixFile[] files = new UnixFile[len];
        for (int i = 0; i < len; i++) {
            files[i] = mFiles[i];
        }
        Slave slave = mApplication.newSlave(pairId, files, mPermissions, mLinks,
                                            mListener, mActiveSignals);
        new Thread(slave).start();

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = slave.getPid().toInteger();

        return result;
    }

    public void doExit(int rval) throws IOException {
        mLogger.info(String.format("exit(rval=%d)", rval));
        mExitStatus = Integer.valueOf(rval);
    }

    public SyscallResult.Wait4 doWait4(int pid, int options) throws IOException {
        mLogger.info(String.format("wait4(pid=%d, options=%d)", pid, options));
        SyscallResult.Wait4 result = new SyscallResult.Wait4();

        Slave slave;
        try {
            slave = mApplication.waitChildTerminating(new Pid(pid));
        }
        catch (InterruptedException _) {
            result.setError(Errno.EINTR);
            return result;
        }
        if (slave == null) {
            result.setError(Errno.EINVAL);
            return result;
        }

        result.retval = slave.getPid().toInteger();
        result.status = Unix.W_EXITCODE(slave.getExitStatus().intValue(), 0);
        result.rusage = new Unix.Rusage();

        return result;
    }

    private void writeOpenedFileDescriptors() throws IOException {
        int fds[] = { 0, 1, 2 };
        byte[][] buffers = new byte[fds.length][];
        for (int i = 0; i < fds.length; i++) {
            buffers[i] = Encoder.encodeInteger(fds[i]);
        }
        int len = 0;
        for (int i = 0; i < fds.length; i++) {
            len += buffers[i].length;
        }

        mOut.write(len);
        for (int i = 0; i < fds.length; i++) {
            mOut.write(buffers[i]);
        }
    }

    private int findFreeSlotOfFile() {
        int len = mFiles.length;
        int i;
        for (i = 0; (i < len) && (mFiles[i] != null); i++) {
        }
        return i < len ? i : -1;
    }

    private UnixFile getFile(int fd) {
        try {
            return mFiles[fd];
        }
        catch (IndexOutOfBoundsException _) {
            return null;
        }
    }

    private UnixFile getValidFile(int fd) throws UnixException {
        UnixFile file = getFile(fd);
        if (file == null) {
            throw new UnixException(Errno.EBADF);
        }
        return file;
    }

    private void selectFds(Collection<Integer> dest, Collection<Integer> src, SelectPred pred) throws UnixException {
        for (Integer fd: src) {
            UnixFile file = getValidFile(fd.intValue());
            if (pred.isReady(file)) {
                dest.add(fd);
            }
        }
    }

    private int registerFile(UnixFile file) throws UnixException {
        int fd;
        synchronized (mFiles) {
            fd = findFreeSlotOfFile();
            if (fd < 0) {
                throw new UnixException(Errno.ENFILE);
            }
            mFiles[fd] = file;
        }
        return fd;
    }

    private SyscallResult.Generic32 openActualFile(String path, int flags, int mode) throws IOException {
        String fmt = "open actual file: %s";
        mLogger.info(String.format(fmt, path, flags, mode));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (!mPermissions.isAllowed(path)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        UnixFile file;
        try {
            switch (flags & Unix.Constants.O_ACCMODE) {
            case Unix.Constants.O_RDONLY:
                file = new UnixInputFile(path);
                break;
            case Unix.Constants.O_WRONLY:
                // XXX: Here ignores O_CREAT.
                file = new UnixOutputFile(path);
                break;
            default:
                result.retval = -1;
                result.errno = Errno.EINVAL;
                return result;
            }
        }
        catch (UnixException e) {
            result.retval = -1;
            result.errno = e.getErrno();
            return result;
        }
        int fd;
        try {
            fd = registerFile(file);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        result.retval = fd;

        return result;
    }

    private SyscallResult.Stat statActualFile(String path) throws IOException {
        mLogger.info(String.format("stat actual file: %s", path));

        SyscallResult.Stat result = new SyscallResult.Stat();

        if (!mPermissions.isAllowed(path)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        Unix.Stat stat = new Unix.Stat();
        try {
            stat.st_size = new File(path).length();
        }
        catch (SecurityException e) {
            result.retval = -1;
            result.errno = Errno.EPERM;
            return result;
        }

        result.retval = 0;
        result.ub = stat;
        return result;
    }

    private SyscallResult.Readlink readlinkActualFile(String path, long count) throws IOException {
        mLogger.info(String.format("readlink actual file: %s", path));

        SyscallResult.Readlink result = new SyscallResult.Readlink();

        if (!mPermissions.isAllowed(path)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        result.retval = -1;
        result.errno = Errno.EINVAL;

        return result;
    }

    private SyscallResult.Generic32 accessActualFile(String path, int flags) throws IOException {
        mLogger.info(String.format("access actual file: %s", path));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (!mPermissions.isAllowed(path)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        result.retval = 0;
        return result;
    }

    private void setListener(Listener listener) {
        mListener = listener != null ? listener : Listener.NOP;
    }

    private String makeFsetflString(long arg) {
        return String.format(" (%s)", Unix.Constants.Fsetfl.toString(arg));
    }

    private String makeFcntlArgString(int cmd, long arg) {
        return cmd != Unix.Constants.F_SETFL ?  "" : makeFsetflString(arg);
    }

    private void writeSignaled(Signal sig) throws IOException {
        mOut.write(Command.SIGNALED);
        mOut.write((byte)sig.getNumber());
    }

    private Socket getSocket(int fd) throws GetSocketException {
        UnixFile file = getFile(fd);
        if (file == null) {
            throw new GetSocketException(Errno.EBADF);
        }
        Socket sock;
        try {
            sock = (Socket)file;
        }
        catch (ClassCastException _) {
            throw new GetSocketException(Errno.ENOTSOCK);
        }
        return sock;
    }

    private void initialize(Application application, Pid pid, InputStream hubIn,
                            OutputStream hubOut, UnixFile[] files,
                            Permissions permissions, Links links,
                            Listener listener, SignalSet activeSignals) {
        mApplication = application;
        mPid = pid;
        mIn = new SyscallInputStream(hubIn);
        mOut = new SyscallOutputStream(hubOut);
        mPermissions = permissions;
        mLinks = links;
        setListener(listener);
        mFiles = files;
        mActiveSignals = activeSignals;

        mHelper = new SlaveHelper(this, mIn, mOut);
        mFcntlProcs = new FcntlProcs();
        mFcntlProcs.put(Unix.Constants.F_GETFD, new FGetFdProc());
        mFcntlProcs.put(Unix.Constants.F_SETFD, new FSetFdProc());
        mFcntlProcs.put(Unix.Constants.F_SETFL, new FSetFlProc());
    }

    static {
        mFcntlCommands = new HashMap<Integer, String>();
        mFcntlCommands.put(0, "F_DUPFD");
        mFcntlCommands.put(1, "F_GETFD");
        mFcntlCommands.put(2, "F_SETFD");
        mFcntlCommands.put(3, "F_GETFL");
        mFcntlCommands.put(4, "F_SETFL");
        mFcntlCommands.put(5, "F_GETOWN");
        mFcntlCommands.put(7, "F_OGETLK");
        mFcntlCommands.put(8, "F_OSETLK");
        mFcntlCommands.put(9, "F_OSETLKW");
        mFcntlCommands.put(10, "F_DUP2FD");
        mFcntlCommands.put(11, "F_GETLK");
        mFcntlCommands.put(12, "F_SETLK");
        mFcntlCommands.put(13, "F_SETLKW");
        mFcntlCommands.put(14, "F_SETLK_REMOTE");
        mFcntlCommands.put(15, "F_READAHEAD");
        mFcntlCommands.put(16, "F_RDAHEAD");

        mLogger = new Logging.Logger("Slave");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=java
 */
