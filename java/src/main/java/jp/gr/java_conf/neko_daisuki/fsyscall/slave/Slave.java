package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.TimeZone;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/*
 * Android 3.2.1 does not have UnixSystem.
 */
//import com.sun.security.auth.module.UnixSystem;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;
import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.KEvent;
import jp.gr.java_conf.neko_daisuki.fsyscall.KEventArray;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.PollFd;
import jp.gr.java_conf.neko_daisuki.fsyscall.PollFds;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.SignalSet;
import jp.gr.java_conf.neko_daisuki.fsyscall.SocketAddress;
import jp.gr.java_conf.neko_daisuki.fsyscall.SocketLevel;
import jp.gr.java_conf.neko_daisuki.fsyscall.SocketOption;
import jp.gr.java_conf.neko_daisuki.fsyscall.SocketOptions;
import jp.gr.java_conf.neko_daisuki.fsyscall.SyscallResult;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixDomainAddress;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallInputStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallOutputStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.ByteUtil;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.NormalizedPath;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.StringUtil;

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

    private interface TimeoutRunner {

        public enum Action { CONTINUE, BREAK };

        public Action run() throws IOException, UnixException;
    }

    private class TimeoutLoop {

        private TimeoutDetector mDetector;

        public TimeoutLoop(Unix.TimeSpec timeout) {
            mDetector = timeout != null ? new TrueTimeoutDetector(timeout)
                                        : new InfinityTimeoutDetector();
        }

        public TimeoutLoop(int timeout) {
            switch (timeout) {
            case Unix.Constants.INFTIM:
                mDetector = new InfinityTimeoutDetector();
                break;
            case 0:
                mDetector = new ZeroTimeoutDetector();
                break;
            default:
                mDetector = new TrueTimeoutDetector(timeout);
                break;
            }
        }

        public void run(TimeoutRunner runner) throws IOException,
                                                     InterruptedException,
                                                     UnixException {
            TimeoutRunner.Action act = runner.run();
            int interval = 10;  // msec
            long t = 1000 * interval; // usec
            while (!mDetector.isTimeout(t) && (act == TimeoutRunner.Action.CONTINUE) && !mCancelled) {
                Thread.sleep(interval);
                t += 1000 * interval;
                act = runner.run();
            }
        }
    }

    private interface EventFilter {

        public KEvent scan(long ident, boolean clear, long fflags) throws UnixException;
    }

    public class NoSysEventFilter implements EventFilter {

        @Override
        public KEvent scan(long ident, boolean clear, long fflags) throws UnixException {
            throw new UnixException(Errno.ENOSYS);
        }
    }

    public class ReadEventFilter extends NoSysEventFilter {
    }

    public class WriteEventFilter extends NoSysEventFilter {
    }

    public class AioEventFilter extends NoSysEventFilter {
    }

    public class VNodeEventFilter extends NoSysEventFilter {
    }

    public class ProcEventFilter extends NoSysEventFilter {
    }

    public class SignalEventFilter extends NoSysEventFilter {
    }

    public class TimerEventFilter extends NoSysEventFilter {
    }

    public class NetDevEventFilter extends NoSysEventFilter {
    }

    public class FsEventFilter extends NoSysEventFilter {
    }

    public class LioEventFilter extends NoSysEventFilter {
    }

    public class UserEventFilter extends NoSysEventFilter {
    }

    private class EventFilters {

        private Map<Short, EventFilter> mFilters;

        public EventFilters() {
            mFilters = new HashMap<Short, EventFilter>();
            put(KEvent.EVFILT_READ, new ReadEventFilter());
            put(KEvent.EVFILT_WRITE, new WriteEventFilter());
            put(KEvent.EVFILT_AIO, new AioEventFilter());
            put(KEvent.EVFILT_VNODE, new VNodeEventFilter());
            put(KEvent.EVFILT_PROC, new ProcEventFilter());
            put(KEvent.EVFILT_SIGNAL, new SignalEventFilter());
            put(KEvent.EVFILT_TIMER, new TimerEventFilter());
            put(KEvent.EVFILT_NETDEV, new NetDevEventFilter());
            put(KEvent.EVFILT_FS, new FsEventFilter());
            put(KEvent.EVFILT_LIO, new LioEventFilter());
            put(KEvent.EVFILT_USER, new UserEventFilter());
        }

        public EventFilter get(short filter) throws UnixException {
            EventFilter ef = mFilters.get(Short.valueOf(filter));
            if (ef == null) {
                throw new UnixException(Errno.EINVAL);
            }
            return ef;
        }

        private void put(short filter, EventFilter ef) {
            mFilters.put(Short.valueOf(filter), ef);
        }
    }

    private class KQueue extends UnixFile {

        private class Event {

            private long mIdent;
            private short mFilter;
            private long mFilterFlags;
            private boolean mEnabled;
            private boolean mOneShot;
            private boolean mClear;
            private long mData;

            public Event(long ident, short filter, long fflags, boolean enabled,
                         boolean oneShot, boolean clear, long data) {
                mIdent = ident;
                mFilter = filter;
                setFilterFlags(fflags);
                setEnabled(enabled);
                mOneShot = oneShot;
                mClear = clear;
                setData(data);
            }

            public long getIdent() {
                return mIdent;
            }

            public short getFilter() {
                return mFilter;
            }

            public void enable() {
                setEnabled(true);
            }

            public void disable() {
                setEnabled(false);
            }

            public boolean isEnabled() {
                return mEnabled;
            }

            public long getFilterFlags() {
                return mFilterFlags;
            }

            public void setFilterFlags(long fflags) {
                mFilterFlags = fflags;
            }

            public boolean isOneShot() {
                return mOneShot;
            }

            public void setOneShot() {
                mOneShot = true;
            }

            public boolean isClear() {
                return mClear;
            }

            public void setClear() {
                mClear = true;
            }

            public long getData() {
                return mData;
            }

            public void setData(long data) {
                mData = data;
            }

            private void setEnabled(boolean enabled) {
                mEnabled = enabled;
            }
        }

        private class Events implements Iterable<Event> {

            private class Key {

                private long mIdent;
                private short mFilter;

                public Key(long ident, short filter) {
                    mIdent = ident;
                    mFilter = filter;
                }

                public Key(KEvent kev) {
                    this(kev.ident, kev.filter);
                }

                @Override
                public boolean equals(Object o) {
                    Key key;
                    try {
                        key = (Key)o;
                    }
                    catch (ClassCastException unused) {
                        return false;
                    }
                    return (mIdent == key.mIdent) && (mFilter == key.mFilter);
                }

                @Override
                public int hashCode() {
                    int n = Long.valueOf(mIdent).hashCode();
                    int m = Short.valueOf(mFilter).hashCode();
                    return n + m;
                }
            }

            private Map<Key, Event> mEvents = new HashMap<Key, Event>();

            @Override
            public Iterator<Event> iterator() {
                return mEvents.values().iterator();
            }

            public void change(KEvent kev) throws UnixException {
                Key key = new Key(kev);
                int flags = kev.flags;
                if ((flags & KEvent.EV_ADD) != 0) {
                    add(key, kev);
                    return;
                }

                Event entry = mEvents.get(key);
                if (entry == null) {
                    throw new UnixException(Errno.ENOENT);
                }
                if ((flags & KEvent.EV_DELETE) != 0) {
                    mEvents.remove(key);
                    return;
                }

                entry.setFilterFlags(kev.fflags);
                if ((flags & KEvent.EV_ENABLE) != 0) {
                    entry.enable();
                }
                if ((flags & KEvent.EV_DISABLE) != 0) {
                    entry.disable();
                }
                if ((flags & KEvent.EV_ONESHOT) != 0) {
                    entry.setOneShot();
                }
                if ((flags & KEvent.EV_CLEAR) != 0) {
                    entry.setClear();
                }
                if ((flags & KEvent.EV_RECEIPT) != 0) {
                    // TODO
                }
                if ((flags & KEvent.EV_DISPATCH) != 0) {
                    // TODO
                }
                entry.setData(kev.data);
            }

            private void add(Key key, KEvent kev) {
                int flags = kev.flags;
                Event entry = new Event(kev.ident, kev.filter, kev.fflags,
                                        (flags & KEvent.EV_DISABLE) == 0,
                                        (flags & KEvent.EV_ONESHOT) != 0,
                                        (flags & KEvent.EV_CLEAR) != 0,
                                        kev.data);
                mEvents.put(key, entry);
            }
        }

        private class Runner implements TimeoutRunner {

            private int mMax;
            private Collection<KEvent> mResults = new HashSet<KEvent>();

            public Runner(int nevents) {
                mMax = nevents;
            }

            public Collection<KEvent> getEvents() {
                return mResults;
            }

            public Action run() throws UnixException {
                for (Event ev: mEvents) {
                    if (!ev.isEnabled()) {
                        continue;
                    }
                    EventFilter filter = mEventFilters.get(ev.getFilter());
                    long ident = ev.getIdent();
                    long fflags = ev.getFilterFlags();
                    KEvent kev = filter.scan(ident, ev.isClear(), fflags);
                    if (kev == null) {
                        continue;
                    }
                    mResults.add(kev);
                    if (mResults.size() == mMax) {
                        break;
                    }
                }
                return 0 < mResults.size() ? Action.BREAK : Action.CONTINUE;
            }
        }

        private Events mEvents = new Events();

        public KQueue(Alarm alarm) {
            super(alarm);
        }

        public boolean isReadyToRead() throws UnixException {
            return false;
        }

        public boolean isReadyToWrite() throws UnixException {
            return false;
        }

        public int read(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.ENXIO);
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            throw new UnixException(Errno.ENXIO);
        }

        public long lseek(long offset, int whence) throws UnixException {
            throw new UnixException(Errno.ESPIPE);
        }

        public Unix.Stat fstat() throws UnixException {
            // TODO: Implement.
            throw new UnixException(Errno.ENOSYS);
        }

        public Collection<KEvent> kevent(KEventArray changelist, int nevents,
                                         Unix.TimeSpec timeout) throws IOException, InterruptedException, UnixException {
            change(changelist);
            return nevents == 0 ? new HashSet<KEvent>()
                                : scan(nevents, timeout);
        }

        @Override
        public void clearFilterFlags() {
            // nothing.
        }

        @Override
        public long getFilterFlags() {
            return 0L;
        }

        protected int doWrite(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.ENXIO);
        }

        protected void doClose() throws UnixException {
            // nothing?
        }

        private void change(KEventArray changelist) throws UnixException {
            for (KEvent kev: changelist) {
                mEvents.change(kev);
            }
        }

        private Collection<KEvent> scan(int nevents, Unix.TimeSpec timeout) throws IOException, InterruptedException, UnixException {
            Runner runner = new Runner(nevents);
            new TimeoutLoop(timeout).run(runner);
            return runner.getEvents();
        }
    }

    private interface FileRegisteringCallback {

        public UnixFile call() throws UnixException;
    }

    private class OpenResourceCallback implements FileRegisteringCallback {

        private URL mUrl;

        public OpenResourceCallback(URL url) {
            mUrl = url;
        }

        public UnixFile call() throws UnixException {
            String path;
            try {
                path = mApplication.getResourcePath(mUrl);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return new UnixInputFile(mAlarm, path, false);
        }
    }

    private class KQueueCallback implements FileRegisteringCallback {

        public UnixFile call() throws UnixException {
            return new KQueue(mAlarm);
        }
    }

    private class SocketCallback implements FileRegisteringCallback {

        private int mDomain;
        private int mType;
        private int mProtocol;

        public SocketCallback(int domain, int type, int protocol) {
            mDomain = domain;
            mType = type;
            mProtocol = protocol;
        }

        public UnixFile call() throws UnixException {
            return new Socket(mAlarm, mDomain, mType, mProtocol);
        }
    }

    private class OpenCallback implements FileRegisteringCallback {

        private NormalizedPath mPath;
        private int mFlags;

        public OpenCallback(NormalizedPath path, int flags) {
            mPath = path;
            mFlags = flags;
        }

        public UnixFile call() throws UnixException {
            UnixFile file;

            switch (mFlags & Unix.Constants.O_ACCMODE) {
            case Unix.Constants.O_RDONLY:
                boolean create = (mFlags & Unix.Constants.O_CREAT) != 0;
                file = new UnixInputFile(mAlarm, mPath.toString(), create);
                break;
            case Unix.Constants.O_WRONLY:
                // XXX: Here ignores O_CREAT.
                file = new UnixOutputFile(mAlarm, mPath.toString());
                break;
            default:
                throw new UnixException(Errno.EINVAL);
            }

            return file;
        }
    }

    private class AcceptCallback implements FileRegisteringCallback {

        private Socket mSocket;
        private Socket mClientSocket;

        public AcceptCallback(Socket socket) {
            mSocket = socket;
        }

        public UnixFile call() throws UnixException {
            mClientSocket = mSocket.accept();
            return mClientSocket;
        }

        public Socket getClientSocket() {
            return mClientSocket;
        }
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

    private static abstract class TimeoutDetector {

        public abstract boolean isTimeout(long usec);

        public static TimeoutDetector newInstance(Unix.TimeSpec timeout) {
            return timeout != null ? new TrueTimeoutDetector(timeout)
                                   : new InfinityTimeoutDetector();
        }

        public static TimeoutDetector newInstance(long timeout) {
            if (timeout == Unix.Constants.INFTIM) {
                return new InfinityTimeoutDetector();
            }
            else if (timeout == 0L) {
                return new ZeroTimeoutDetector();
            }
            return new TrueTimeoutDetector(timeout);
        }
    }

    private static class ZeroTimeoutDetector extends TimeoutDetector {

        private int mCount = 0;

        public boolean isTimeout(long usec) {
            boolean timeouted = 0 < mCount;
            mCount++;
            return timeouted;
        }
    }

    private static class InfinityTimeoutDetector extends TimeoutDetector {

        public boolean isTimeout(long usec) {
            return false;
        }
    }

    private static class TrueTimeoutDetector extends TimeoutDetector {

        private long mTime; // usec

        public TrueTimeoutDetector(Unix.TimeVal timeout) {
            mTime = 1000000 * timeout.tv_sec + timeout.tv_usec;
        }

        public TrueTimeoutDetector(Unix.TimeSpec timeout) {
            mTime = 1000000 * timeout.tv_sec + timeout.tv_nsec / 1000;
        }

        public TrueTimeoutDetector(long msec) {
            mTime = 1000 * msec;
        }

        public boolean isTimeout(long usec) {
            return mTime <= usec;
        }
    }

    private class Socket extends UnixFile {

        public class Control {

            private Unix.Cmsghdr mCmsghdr;
            private UnixFile[] mFiles;

            public Control(Unix.Cmsghdr cmsghdr) {
                mCmsghdr = cmsghdr;
            }

            public Control(Unix.Cmsghdr cmsghdr, UnixFile[] files) {
                this(cmsghdr);
                mFiles = files;
            }

            public Unix.Cmsghdr getCmsghdr() {
                return mCmsghdr;
            }

            public UnixFile[] getFiles() {
                return mFiles;
            }
        }

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

        private class ControlBuffer {

            public class Writer {

                public void write(Control control) throws InterruptedException {
                    synchronized (mQueue) {
                        mQueue.put(control);
                    }
                }
            }

            public class Reader {

                public Control read() throws InterruptedException {
                    synchronized (mQueue) {
                        return mQueue.take();
                    }
                }
            }

            private BlockingQueue<Control> mQueue;
            private Reader mReader = new Reader();
            private Writer mWriter = new Writer();

            public ControlBuffer() {
                mQueue = new LinkedBlockingQueue<Control>();
            }

            public Reader getReader() {
                return mReader;
            }

            public Writer getWriter() {
                return mWriter;
            }
        }

        private class ConnectingRequest {

            private Socket mPeer;
            private Pair mPair;
            private ControlBuffer mControlBufferFromClient;
            private ControlBuffer mControlBufferFromServer;

            public ConnectingRequest(Socket peer) {
                mPeer = peer;
                mControlBufferFromClient = new ControlBuffer();
                mControlBufferFromServer = new ControlBuffer();
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

            public ControlBuffer getControlBufferFromServer() {
                return mControlBufferFromServer;
            }

            public ControlBuffer getControlBufferFromClient() {
                return mControlBufferFromClient;
            }
        }

        private int mDomain;
        private int mType;
        private int mProtocol;
        private SocketAddress mName;
        private Socket mPeer;
        private SocketOptions mOptions = new SocketOptions();

        private SocketCore mCore;
        private ControlBuffer.Reader mControlReader;
        private ControlBuffer.Writer mControlWriter;
        private Queue<ConnectingRequest> mConnectingRequests;

        public Socket(Alarm alarm, int domain, int type, int protocol) {
            super(alarm);
            mDomain = domain;
            mType = type;
            mProtocol = protocol;
        }

        public Socket(Alarm alarm, int domain, int type, int protocol,
                      SocketAddress name, Socket peer) {
            this(alarm, domain, type, protocol);
            setName(name);
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

        public void setName(SocketAddress name) {
            mName = name;
        }

        public void setCore(SocketCore core) {
            mCore = core;
        }

        public boolean isReadyToRead() throws UnixException {
            if (mConnectingRequests != null) {
                synchronized (mConnectingRequests) {
                    return !mConnectingRequests.isEmpty();
                }
            }

            InputStream in = mCore.getInputStream();
            if (in == null) {
                throw new UnixException(Errno.ENOTCONN);
            }
            try {
                return 0 < in.available();
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
            InputStream in = mCore.getInputStream();
            if (in == null) {
                throw new UnixException(Errno.ENOTCONN);
            }
            try {
                return in.read(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            int len = buffer.length;
            InputStream in = mCore.getInputStream();
            if (in == null) {
                throw new UnixException(Errno.ENOTCONN);
            }
            try {
                return in.read(buffer, (int)offset, len);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        public long lseek(long offset, int whence) throws UnixException {
            return offset;
        }

        public Unix.Stat fstat() throws UnixException {
            Unix.Stat st = new Unix.Stat();
            st.st_dev = -1;
            st.st_mode = Unix.Constants.S_IRUSR
                       | Unix.Constants.S_IWUSR
                       | Unix.Constants.S_IRGRP
                       | Unix.Constants.S_IWGRP
                       | Unix.Constants.S_IROTH
                       | Unix.Constants.S_IWOTH
                       | Unix.Constants.S_IFDIR
                       | Unix.Constants.S_IFBLK
                       | Unix.Constants.S_IFREG
                       | Unix.Constants.S_IFLNK
                       | Unix.Constants.S_IFSOCK
                       | Unix.Constants.S_IFWHT;
            st.st_uid = UID;
            st.st_gid = GID;
            st.st_blksize = 8192;

            return st;
        }

        public void connect(UnixDomainAddress addr) throws UnixException {
            String addrPath = addr.getPath();
            NormalizedPath path;
            try {
                path = getActualPath(addrPath);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            Socket peer = (Socket)mApplication.getUnixDomainSocket(path);
            setName(new UnixDomainAddress(2, addr.getFamily(), ""));
            connect(peer);
        }

        public void connect(Socket peer) throws UnixException {
            Queue<ConnectingRequest> queue = peer.mConnectingRequests;
            if (queue == null) {
                throw new UnixException(Errno.EINVAL);
            }

            ConnectingRequest request = new ConnectingRequest(this);
            synchronized (queue) {
                // Wake up the accept(2)'ing thread.
                queue.offer(request);
                queue.notifyAll();
            }
            // Wake up the poll(2)'ing thread before accept(2).
            getAlarm().alarm();

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
            mControlReader = request.getControlBufferFromServer().getReader();
            mControlWriter = request.getControlBufferFromClient().getWriter();

            // The accepting side sets mPeer of this socket.
        }

        public void bind(UnixDomainAddress addr) throws UnixException {
            if (mName != null) {
                throw new UnixException(Errno.EINVAL);
            }
            mConnectingRequests = new LinkedList<ConnectingRequest>();
            String addrPath = addr.getPath();
            NormalizedPath path;
            try {
                path = getActualPath(addrPath);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            mApplication.bindSocket(path, this);
            setCore(new LocalBoundCore());
            setName(addr);
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

            Socket socket = new Socket(getAlarm(), mDomain, mType, mProtocol,
                                       mName, peer);
            Pair pair = new Pair(c2s.getInputStream(), s2c.getOutputStream());
            socket.mControlReader = request.getControlBufferFromClient().getReader();
            socket.mControlWriter = request.getControlBufferFromServer().getWriter();
            socket.setCore(new PipeCore(pair));

            return socket;
        }

        public void listen(int backlog) throws UnixException {
            // does nothing.
        }

        public void addOption(SocketOption option) {
            mOptions.add(option);
        }

        public void removeOption(SocketOption option) {
            mOptions.remove(option);
        }

        public boolean containsOption(SocketOption option) {
            return mOptions.contains(option);
        }

        @Override
        public void clearFilterFlags() {
            // TODO
        }

        @Override
        public long getFilterFlags() {
            return 0L;
        }

        public long recvmsg(byte[] buf,
                            Unix.Cmsghdr[] control) throws UnixException {
            long nbytes = read(buf);

            if ((control != null) && (0 < control.length)) {
                Socket.Control cntl;
                try {
                    cntl = mControlReader.read();
                }
                catch (InterruptedException e) {
                    throw new UnixException(Errno.EINTR, e);
                }
                Unix.Cmsghdr cmsghdr = cntl.getCmsghdr();
                switch (cmsghdr.cmsg_level) {
                case Unix.Constants.SOL_SOCKET:
                    switch (cmsghdr.cmsg_type) {
                    case Unix.Constants.SCM_CREDS:
                        break;
                    case Unix.Constants.SCM_RIGHTS:
                        int[] fds = registerFiles(cntl.getFiles());
                        cmsghdr.cmsg_data = new Unix.Cmsgfds(fds);
                        break;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }
                control[0] = cmsghdr;
            }

            return nbytes;
        }

        public long sendmsg(Unix.Msghdr msg) throws UnixException {
            Unix.Cmsghdr[] control = msg.msg_control;
            Unix.Cmsghdr[] cmsghdrs = control != null ? control
                                                      : new Unix.Cmsghdr[0];
            int ncmsghdrs = cmsghdrs.length;
            for (int i = 0; i < ncmsghdrs; i++) {
                Unix.Cmsghdr cmsghdr = cmsghdrs[i];
                switch (cmsghdr.cmsg_level) {
                case Unix.Constants.SOL_SOCKET:
                    switch (cmsghdr.cmsg_type) {
                    case Unix.Constants.SCM_CREDS:
                        writeCreds(cmsghdr);
                        break;
                    case Unix.Constants.SCM_RIGHTS:
                        writeRights(cmsghdr);
                        break;
                    default:
                        throw new UnixException(Errno.EOPNOTSUPP);
                    }
                    break;
                default:
                    throw new UnixException(Errno.EOPNOTSUPP);
                }
            }

            int nbytes = 0;
            int iovlen = msg.msg_iov.length;
            for (int i = 0; i < iovlen; i++) {
                Unix.IoVec iov = msg.msg_iov[i];
                nbytes += write(iov.iov_base);
            }

            return nbytes;
        }

        public String toString() {
            String domain;
            switch (mDomain) {
            case Unix.Constants.PF_LOCAL:
                domain = "PF_LOCAL";
                break;
            default:
                domain = "unknown";
                break;
            }
            String type;
            switch (mType) {
            case Unix.Constants.SOCK_STREAM:
                type = "SOCK_STREAM";
                break;
            default:
                type = "unknown";
                break;
            }

            String state;
            if (mName != null) {
                String fmt = mPeer != null ? "connected with %s"
                                           : "bound to %s";
                state = String.format(fmt, mName);
            }
            else {
                state = "disconnected";
            }
            String fmt = "Socket(domain=%d (%s), type=%d (%s), protocol=%d, %s)";
            return String.format(fmt, mDomain, domain, mType, type, mProtocol,
                                 state);
        }

        protected int doWrite(byte[] buffer) throws UnixException {
            OutputStream out = mCore.getOutputStream();
            if (out == null) {
                throw new UnixException(Errno.ENOTCONN);
            }
            try {
                out.write(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return buffer.length;
        }

        protected void doClose() throws UnixException {
            try {
                mCore.close();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }

        private void writeRights(Unix.Cmsghdr cmsghdr) throws UnixException {
            Unix.Cmsgfds data = (Unix.Cmsgfds)cmsghdr.cmsg_data;
            int[] fds = data.fds;
            UnixFile[] files = getLockedFiles(fds);
            try {
                int len = fds.length;
                for (int i = 0; i < len; i++) {
                    files[i].incRefCount();
                }

                Unix.Cmsghdr copy = new Unix.Cmsghdr(cmsghdr);
                Socket.Control control = new Socket.Control(copy, files);
                try {
                    mControlWriter.write(control);
                }
                catch (InterruptedException e) {
                    throw new UnixException(Errno.EINTR, e);
                }
            }
            finally {
                int len = fds.length;
                for (int i = 0; i < len; i++) {
                    files[i].unlock();
                }
            }
        }

        private void writeCreds(Unix.Cmsghdr cmsghdr) throws UnixException {
            int[] groups = new int[] { GID };
            Unix.Cmsgdata data = new Unix.Cmsgcred(mPid, UID, UID, GID, groups);
            cmsghdr.cmsg_data = data;
            Unix.Cmsghdr copy = new Unix.Cmsghdr(cmsghdr);
            Socket.Control control = new Socket.Control(copy);
            try {
                mControlWriter.write(control);
            }
            catch (InterruptedException e) {
                throw new UnixException(Errno.EINTR, e);
            }
        }
    }

    private class ExternalPeer extends Socket {

        public ExternalPeer(Alarm alarm, int domain, int type, int protocol,
                            SocketAddress name, Socket peer) {
            super(alarm, domain, type, protocol, name, peer);
        }
    }

    private abstract static class UnixRandomAccessFile extends UnixFile {

        protected RandomAccessFile mFile;

        protected UnixRandomAccessFile(Alarm alarm, String path,
                                       String mode) throws UnixException {
            super(alarm);

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

        public UnixInputFile(Alarm alarm, String path,
                             boolean create) throws UnixException {
            super(alarm, path, create ? "rw" : "r");
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

        @Override
        public void clearFilterFlags() {
            // does nothing.
        }

        @Override
        public long getFilterFlags() {
            return 0L;
        }

        protected int doWrite(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }
    }

    private static class UnixOutputFile extends UnixRandomAccessFile {

        private long mFilterFlags;

        public UnixOutputFile(Alarm alarm, String path) throws UnixException {
            super(alarm, path, "rw");
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

        @Override
        public void clearFilterFlags() {
            mFilterFlags = 0;
        }

        @Override
        public long getFilterFlags() {
            return mFilterFlags;
        }

        protected int doWrite(byte[] buffer) throws UnixException {
            try {
                mFile.write(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            mFilterFlags |= KEvent.NOTE_WRITE;
            return buffer.length;
        }
    }

    private abstract static class UnixStream extends UnixFile {

        public UnixStream(Alarm alarm) {
            super(alarm);
        }

        public long lseek(long offset, int whence) throws UnixException {
            throw new UnixException(Errno.ESPIPE);
        }

        public Unix.Stat fstat() throws UnixException {
            throw new UnixException(Errno.ESPIPE);
        }
    }

    private static class UnixInputStream extends UnixStream {

        private InputStream mIn;

        public UnixInputStream(Alarm alarm, InputStream in) {
            super(alarm);
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

        @Override
        public void clearFilterFlags() {
            // does nothing.
        }

        @Override
        public long getFilterFlags() {
            return 0L;
        }

        protected int doWrite(byte[] buffer) throws UnixException {
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
        private long mFilterFlags;

        public UnixOutputStream(Alarm alarm, OutputStream out) {
            super(alarm);
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

        @Override
        public void clearFilterFlags() {
            mFilterFlags = 0;
        }

        @Override
        public long getFilterFlags() {
            return mFilterFlags;
        }

        protected int doWrite(byte[] buffer) throws UnixException {
            try {
                mOut.write(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            mFilterFlags |= KEvent.NOTE_WRITE;
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

    private interface AlarmReaction {

        public int run() throws IOException, UnixException;
    }

    private class AlarmReactor {

        public static final int ACTION_BREAK = 0;
        public static final int ACTION_CONTINUE = 1;

        private static final long INFTIM = Unix.Constants.INFTIM;

        private AlarmReaction mReaction;
        private Unix.TimeSpec mTimeout;

        public AlarmReactor(AlarmReaction reaction, long timeout /* msec */) {
            setReaction(reaction);

            if (timeout != Unix.Constants.INFTIM) {
                int sec = (int)(timeout / 1000);
                long nsec = (timeout % 1000) * 1000000;
                mTimeout = new Unix.TimeSpec(sec, nsec);
            }
        }

        public AlarmReactor(AlarmReaction reaction, Unix.TimeVal timeout) {
            setReaction(reaction);

            if (timeout != null) {
                int sec = (int)timeout.tv_sec;
                long nsec = 1000 * timeout.tv_usec;
                mTimeout = new Unix.TimeSpec(sec, nsec);
            }
        }

        public void run() throws IOException, UnixException {
            long t0 = System.nanoTime();
            long nanoTimeout = mTimeout != null ? mTimeout.toNanoTime() : 0;
            synchronized (mAlarm) {
                while (true) {
                    int action = mReaction.run();
                    switch (action) {
                    case ACTION_BREAK:
                        return;
                    case ACTION_CONTINUE:
                        break;
                    default:
                        String fmt = "unsupported action: %d";
                        throw new RuntimeException(String.format(fmt, action));
                    }

                    long t = System.nanoTime() - t0;
                    if ((mTimeout != null) && (nanoTimeout <= t)) {
                        return;
                    }
                    if (mCancelled) {
                        throw new UnixException(Errno.EINTR);
                    }
                    long nano = mTimeout != null ? nanoTimeout - t : 0;
                    try {
                        mAlarm.wait(nano / 1000000, (int)(nano % 1000000));
                    }
                    catch (InterruptedException e) {
                        throw new UnixException(Errno.EINTR, e);
                    }
                }
            }
        }

        private void setReaction(AlarmReaction reaction) {
            mReaction = reaction;
        }
    }

    private class PollReaction implements AlarmReaction {

        private PollFds mFds;
        private UnixFile[] mFiles;
        private int mReadyFdsNumber;

        public PollReaction(PollFds fds, UnixFile[] files) {
            mFds = fds;
            mFiles = files;
        }

        public int getReadyFdsNumber() {
            return mReadyFdsNumber;
        }

        public int run() throws IOException, UnixException {
            int nReadyFds = 0;
            int nFiles = mFds.size();
            for (int i = 0; i < nFiles; i++) {
                PollFd fd = mFds.get(i);
                UnixFile file = mFiles[i];
                file.lock();
                try {
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
                finally {
                    file.unlock();
                }
                nReadyFds += (fd.getRevents() != 0 ? 1 : 0);
            }

            mReadyFdsNumber = nReadyFds;

            return 0 < nReadyFds ? AlarmReactor.ACTION_BREAK
                                 : AlarmReactor.ACTION_CONTINUE;
        }
    }

    private class InterruptablePollReaction extends PollReaction {

        public InterruptablePollReaction(PollFds fds, UnixFile[] files) {
            super(fds, files);
        }

        public int run() throws IOException, UnixException {
            boolean isBreak = super.run() == AlarmReactor.ACTION_BREAK;
            return isBreak || mIn.isReady() ? AlarmReactor.ACTION_BREAK
                                            : AlarmReactor.ACTION_CONTINUE;
        }
    }

    private class SelectReaction implements AlarmReaction {

        private Unix.Fdset mInReady = new Unix.Fdset();
        private Unix.Fdset mOuReady = new Unix.Fdset();
        private Unix.Fdset mExReady = new Unix.Fdset();
        private Unix.Fdset mIn;
        private UnixFile[] mInFiles;
        private Unix.Fdset mOu;
        private UnixFile[] mOuFiles;
        private Unix.Fdset mEx;
        private UnixFile[] mExFiles;

        public SelectReaction(Unix.Fdset in, UnixFile[] inFiles, Unix.Fdset ou,
                              UnixFile[] ouFiles, Unix.Fdset ex,
                              UnixFile[] exFiles) {
            mIn = in;
            mInFiles = inFiles;
            mOu = ou;
            mOuFiles = ouFiles;
            mEx = ex;
            mExFiles = exFiles;
        }

        public Unix.Fdset getInReady() {
            return mInReady;
        }

        public Unix.Fdset getOuReady() {
            return mOuReady;
        }

        public Unix.Fdset getExReady() {
            return mExReady;
        }

        public int getReadyFdsNumber() {
            return mInReady.size() + mOuReady.size() + mExReady.size();
        }

        public int run() throws IOException, UnixException {
            mInReady.clear();
            mOuReady.clear();
            mExReady.clear();

            selectFds(mInReady, mIn, mInFiles, READ_SELECT_PRED);
            selectFds(mOuReady, mOu, mOuFiles, WRITE_SELECT_PRED);
            // TODO: Perform for ex (But how?).

            return 0 < getReadyFdsNumber() ? AlarmReactor.ACTION_BREAK
                                           : AlarmReactor.ACTION_CONTINUE;
        }

        private void selectFds(Unix.Fdset ready, Unix.Fdset fds,
                               UnixFile[] files, SelectPred pred) throws UnixException {
            int nfds = fds.size();
            for (int i = 0; i < nfds; i++) {
                UnixFile file = files[i];
                file.lock();
                try {
                    if (pred.isReady(file)) {
                        ready.add(fds.get(i));
                    }
                }
                finally {
                    file.unlock();
                }
            }
        }
    }

    private static final int UID = 1001;
    private static final int GID = 1001;
    private static final int UNIX_FILE_NUM = 256;
    private static final String CHARS[] = {
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", "!", "\"", "#", "$", "%", "&", "'",
            "(", ")", "*", "+", ",", "-", ".", "/",
            "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", ":", ";", "<", "=", ">", "?",
            "@", "A", "B", "C", "D", "E", "F", "G",
            "H", "I", "J", "K", "L", "M", "N", "O",
            "P", "Q", "R", "S", "T", "U", "V", "W",
            "X", "Y", "Z", "[", "\\", "]", "^", "_",
            "`", "a", "b", "c", "d", "e", "f", "g",
            "h", "i", "j", "k", "l", "m", "n", "o",
            "p", "q", "r", "s", "t", "u", "v", "w",
            "x", "y", "z", "{", "|", "}", "~", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " ",
            " ", " ", " ", " ", " ", " ", " ", " "
    };
    private static final SelectPred READ_SELECT_PRED = new ReadSelectPred();
    private static final SelectPred WRITE_SELECT_PRED = new WriteSelectPred();

    // static helpers
    private static NormalizedPath mPwdDbPath;
    private static Map<Integer, String> mFcntlCommands;
    private static Logging.Logger mLogger;

    private final FileRegisteringCallback KQUEUE_CALLBACK = new KQueueCallback();

    // settings
    private Application mApplication;
    private SyscallInputStream mIn;
    private SyscallOutputStream mOut;
    private Permissions mPermissions;
    private Links mLinks;
    private Listener mListener;

    // states
    private Pid mPid;
    private State mState = State.NORMAL;
    private NormalizedPath mCurrentDirectory;
    private UnixFile[] mFiles;
    private SignalSet mPendingSignals = new SignalSet();
    private Integer mExitStatus;

    private Alarm mAlarm;

    // helpers
    private SlaveHelper mHelper;
    private FcntlProcs mFcntlProcs;
    private boolean mCancelled = false;
    private EventFilters mEventFilters = new EventFilters();

    public Slave(Application application, Pid pid, InputStream hubIn,
                 OutputStream hubOut, NormalizedPath currentDirectory,
                 InputStream stdin, OutputStream stdout, OutputStream stderr,
                 Permissions permissions, Links links, Listener listener) throws IOException {
        mLogger.info("a slave is starting.");

        Alarm alarm = new Alarm();

        UnixFile[] files = new UnixFile[UNIX_FILE_NUM];
        files[0] = new UnixInputStream(alarm, stdin);
        files[1] = new UnixOutputStream(alarm, stdout);
        files[2] = new UnixOutputStream(alarm, stderr);

        initialize(application, pid, hubIn, hubOut, currentDirectory, files,
                   permissions, links, listener, alarm);

        writeOpenedFileDescriptors();
        mLogger.verbose("file descripters were transfered from the slave.");
    }

    /**
     * Constructor for fork(2).
     */
    public Slave(Application application, Pid pid, InputStream hubIn,
                 OutputStream hubOut, NormalizedPath currentDirectory,
                 UnixFile[] files, Permissions permissions, Links links,
                 Listener listener, Alarm alarm) {
        initialize(application, pid, hubIn, hubOut, currentDirectory, files,
                   permissions, links, listener, alarm);
    }

    public void kill(Signal sig) throws UnixException {
        if (sig == null) {
            throw new UnixException(Errno.EINVAL);
        }
        mPendingSignals.add(sig);
    }

    public Integer getExitStatus() {
        return mExitStatus;
    }

    @Override
    public void run() {
        mLogger.info(String.format("a slave started: pid=%s", mPid));

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
                        catch (InterruptedException unused) {
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
        mAlarm.alarm();
    }

    public Pid getPid() {
        return mPid;
    }

    public boolean isZombie() {
        return mState == State.ZOMBIE;
    }

    public SyscallResult.Generic32 doSigprocmask(int how, SignalSet set) {
        String fmt = "sigprocmask(how=%d (%s), set=%s)";
        String howString;
        switch (how) {
        case Unix.Constants.SIG_BLOCK:
            howString = "SIG_BLOCK";
            break;
        case Unix.Constants.SIG_UNBLOCK:
            howString = "SIG_UNBLOCK";
            break;
        case Unix.Constants.SIG_SETMASK:
            howString = "SIG_SETMASK";
            break;
        default:
            howString = "invalid";
            break;
        }
        mLogger.info(String.format(fmt, how, howString, set));

        return new SyscallResult.Generic32();
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
            sock = getLockedSocket(s);
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
        finally {
            sock.unlock();
        }

        return result;
    }

    public SyscallResult.Generic32 doChdir(String path) throws IOException {
        mLogger.info(String.format("chdir(path=%s)", StringUtil.quote(path)));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        NormalizedPath actPath = getActualPath(path);
        /*
        if (!mPermissions.isAllowed(actPath)) {
            result.setError(Errno.EPERM);
            return result;
        }
        */

        File file = new File(actPath.toString());
        if (!file.isDirectory()) {
            result.setError(file.exists() ? Errno.ENOTDIR : Errno.ENOENT);
            return result;
        }

        mCurrentDirectory = new NormalizedPath(mCurrentDirectory, path);

        return result;
    }

    public SyscallResult.Generic32 doKqueue() throws IOException {
        mLogger.info("kqueue()");
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        registerFile(KQUEUE_CALLBACK, result);

        return result;
    }

    public SyscallResult.Generic32 doOpen(String path, int flags, int mode) throws IOException {
        String fmt = "open(path=%s, flags=0o%o (%s), mode=0o%o (%s))";
        String msg = String.format(fmt, StringUtil.quote(path), flags,
                                   Unix.Constants.Open.toString(flags), mode,
                                   Unix.Constants.Mode.toString(mode));
        mLogger.info(msg);

        return openActualFile(getActualPath(path), flags, mode);
    }

    public SyscallResult.Read doRead(int fd, long nbytes) throws IOException {
        mLogger.info(String.format("read(fd=%d, nbytes=%d)", fd, nbytes));
        SyscallResult.Read result = new SyscallResult.Read();

        UnixFile file = getLockedFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        byte[] buffer;
        try {
            /*
             * This implementation cannot handle the nbytes parameter which is
             * greater than maximum value of int (2^30 - 1).
             */
            buffer = new byte[(int)nbytes];
            try {
                result.retval = file.read(buffer);
            }
            catch (UnixException e) {
                result.setError(e.getErrno());
                return result;
            }
        }
        finally {
            file.unlock();
        }

        int len = (int)result.retval;
        result.buf = Arrays.copyOf(buffer, len);
        logBuffer(String.format("read: fd=%d: result", fd), result.buf, len);

        return result;
    }

    public SyscallResult.Generic64 doLseek(int fd, long offset, int whence) throws IOException {
        String fmt = "lseek(fd=%d, offset=%d, whence=%d)";
        mLogger.info(String.format(fmt, fd, offset, whence));

        SyscallResult.Generic64 result = new SyscallResult.Generic64();

        UnixFile file = getLockedFile(fd);
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
            result.setError(e.getErrno());
            return result;
        }
        finally {
            file.unlock();
        }

        result.retval = pos;

        return result;
    }

    public SyscallResult.Pread doPread(int fd, long nbyte, long offset) throws IOException {
        String fmt = "pread(fd=%d, nbyte=%d, offset=%d)";
        mLogger.info(String.format(fmt, fd, nbyte, offset));

        SyscallResult.Pread result = new SyscallResult.Pread();

        UnixFile file = getLockedFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        byte[] buffer;
        try {
            buffer = new byte[(int)nbyte];
            try {
                result.retval = file.pread(buffer, offset);
            }
            catch (UnixException e) {
                result.setError(e.getErrno());
                return result;
            }
        }
        finally {
            file.unlock();
        }

        int len = (int)result.retval;
        result.buf = Arrays.copyOf(buffer, len);
        logBuffer(String.format("pread: fd=%d: result", fd), result.buf, len);

        return result;
    }

    public SyscallResult.Accept doGetpeername(int s, int namelen) throws IOException {
        String fmt = "getpeername(s=%d, namelen=%d)";
        mLogger.info(String.format(fmt, s, namelen));
        SyscallResult.Accept result = new SyscallResult.Accept();

        Socket socket;
        try {
            socket = getLockedSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }

        try {
            SocketAddress addr = socket.getPeer().getName();
            result.addr = addr;
            result.addrlen = addr.length();
        }
        finally {
            socket.unlock();
        }

        return result;
    }

    public SyscallResult.Accept doGetsockname(int s, int namelen) throws IOException {
        String fmt = "getsockname(s=%d, namelen=%d)";
        mLogger.info(String.format(fmt, s, namelen));
        SyscallResult.Accept result = new SyscallResult.Accept();

        Socket socket;
        try {
            socket = getLockedSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }

        try {
            SocketAddress addr = socket.getName();
            result.addr = addr;
            result.addrlen = addr.length();
        }
        finally {
            socket.unlock();
        }

        return result;
    }

    public SyscallResult.Accept doAccept(int s, int addrlen) throws IOException {
        mLogger.info(String.format("accept(s=%d, addrlen=%d)", s, addrlen));
        SyscallResult.Accept result = new SyscallResult.Accept();

        Socket socket;
        try {
            socket = getLockedSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }

        int fd;
        AcceptCallback callback;
        try {
            callback = new AcceptCallback(socket);
            try {
                fd = registerFile(callback);
            }
            catch (UnixException e) {
                result.setError(e.getErrno());
                return result;
            }
        }
        finally {
            socket.unlock();
        }

        SocketAddress addr = callback.getClientSocket().getPeer().getName();
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
        mLogger.info(String.format("lstat(path=%s)", StringUtil.quote(path)));

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

        UnixFile file = getLockedFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
            result.sb = file.fstat();
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        finally {
            file.unlock();
        }

        return result;
    }

    public SyscallResult.Stat doStat(String path) throws IOException {
        mLogger.info(String.format("stat(path=%s)", StringUtil.quote(path)));
        return statActualFile(getActualPath(path));
    }

    public SyscallResult.Generic32 doBind(int s, UnixDomainAddress addr,
                                          int addrlen) throws IOException {
        String fmt = "bind(s=%d, addr=%s, addrlen=%d)";
        mLogger.info(String.format(fmt, s, addr, addrlen));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        Socket sock;
        try {
            sock = getLockedSocket(s);
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
        finally {
            sock.unlock();
        }

        return result;
    }

    public SyscallResult.Generic32 doSetsockopt(int s, int level, int optname,
                                                int optlen, int optval)
                                                throws IOException {
        String fmt;
        fmt = "%s(s=%d, level=%d (%s), optname=%d (%s), optlen=%d, optval=%d)";
        String levelName = SocketLevel.toString(level);
        String name = SocketOption.toString(optname);
        String message = String.format(fmt, "setsockopt", s, level, levelName,
                                       optname, name, optlen, optval);
        mLogger.info(message);

        return runSetsockopt(s, SocketLevel.valueOf(level),
                             SocketOption.valueOf(optname), optval);
    }

    public SyscallResult.Getsockopt doGetsockopt(int s, int level, int optname,
                                                 int optlen)
                                                 throws IOException {
        String fmt;
        fmt = "getsockopt(s=%d, level=%d (%s), optname=%d (%s), optlen=%d)";
        String levelName = SocketLevel.toString(level);
        String name = SocketOption.toString(optname);
        String message = String.format(fmt, s, level, levelName, optname, name,
                                       optlen);
        mLogger.info(message);

        return runGetsockopt(s, SocketLevel.valueOf(level),
                             SocketOption.valueOf(optname));
    }

    public SyscallResult.Generic32 doConnect(int s, UnixDomainAddress name,
                                             int namelen) throws IOException {
        String fmt = "connect(s=%d, name=%s, namelen=%d)";
        mLogger.info(String.format(fmt, s, name, namelen));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        Socket sock;
        try {
            sock = getLockedSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
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
            sock.setName(name);
            Socket peer = new ExternalPeer(mAlarm, domain, type, protocol, name,
                                           sock);
            sock.setPeer(peer);
        }
        finally {
            sock.unlock();
        }

        return result;
    }

    public SyscallResult.Generic32 doWritev(int fd, Unix.IoVec[] iovec) throws IOException {
        mLogger.info(String.format("writev(fd=%d, iovec)", fd));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        UnixFile file = getLockedFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
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
            logBuffer(String.format("writev: fd=%d", fd), buffer);

            try {
                result.retval = file.write(buffer);
            }
            catch (UnixException e) {
                result.setError(e.getErrno());
                return result;
            }
        }
        finally {
            file.unlock();
        }

        return result;
    }

    public SyscallResult.Generic32 doSocket(int domain, int type, int protocol) throws IOException {
        String fmt = "socket(domain=%d, type=%d, protocol=%d)";
        mLogger.info(String.format(fmt, domain, type, protocol));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        FileRegisteringCallback callback = new SocketCallback(domain, type,
                                                              protocol);
        registerFile(callback, result);

        return result;
    }

    public SyscallResult.Generic32 doPollStart(PollFds fds, int nfds, int timeout) throws IOException {
        String fmt = "interruptable poll(fds=%s, nfds=%d, timeout=%d)";
        mLogger.info(String.format(fmt, fds, nfds, timeout));

        UnixFile[] files;
        try {
            files = getFiles(fds);
        }
        catch (UnixException e) {
            return new SyscallResult.Generic32(e.getErrno());
        }

        return runPoll(new InterruptablePollReaction(fds, files), timeout);
    }

    public SyscallResult.Generic32 doPoll(PollFds fds, int nfds, int timeout) throws IOException {
        String fmt = "poll(fds=%s, nfds=%d, timeout=%d)";
        mLogger.info(String.format(fmt, fds, nfds, timeout));

        UnixFile[] files;
        try {
            files = getFiles(fds);
        }
        catch (UnixException e) {
            return new SyscallResult.Generic32(e.getErrno());
        }

        return runPoll(new PollReaction(fds, files), timeout);
    }

    public SyscallResult.Select doSelect(Unix.Fdset in, Unix.Fdset ou,
                                         Unix.Fdset ex, Unix.TimeVal timeout) throws IOException {
        String fmt = "select(in=%s, ou=%s, ex=%s, timeout=%s)";
        mLogger.info(String.format(fmt, in, ou, ex, timeout));
        SyscallResult.Select result = new SyscallResult.Select();

        UnixFile[] inFiles;
        UnixFile[] ouFiles;
        UnixFile[] exFiles;
        try {
            synchronized (mFiles) {
                inFiles = getFiles(in);
                ouFiles = getFiles(ou);
                exFiles = getFiles(ex);
            }
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        SelectReaction reaction = new SelectReaction(in, inFiles, ou, ouFiles,
                                                     ex, exFiles);
        try {
            new AlarmReactor(reaction, timeout).run();
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        int nReadyFds = reaction.getReadyFdsNumber();
        result.retval = nReadyFds;
        if (nReadyFds == 0) {
            return result;
        }

        result.in = reaction.getInReady();
        result.ou = reaction.getOuReady();
        result.ex = reaction.getExReady();

        return result;
    }

    /**
     * readlink(2) implementation. This returns always EINVAL. Because Java 1.6
     * cannot handle symbolic links.
     */
    public SyscallResult.Readlink doReadlink(String path, long count) throws IOException {
        String fmt = "readlink(path=%s, count=%d)";
        mLogger.info(String.format(fmt, StringUtil.quote(path), count));

        return readlinkActualFile(getActualPath(path), count);
    }

    /**
     * The dummy implementation of access(2).
     */
    public SyscallResult.Generic32 doAccess(String path, int flags) throws IOException {
        String fmt = "access(path=%s, flags=0x%02x)";
        mLogger.info(String.format(fmt, StringUtil.quote(path), flags));

        return accessActualFile(getActualPath(path), flags);
    }

    public SyscallResult.Generic32 doLink(String path1, String path2) throws IOException {
        String s1 = StringUtil.quote(path1);
        String s2 = StringUtil.quote(path2);
        mLogger.info(String.format("link(path1=%s, path2=%s)", s1, s2));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = -1;
        result.errno = Errno.ENOSYS;
        return result;
    }

    public SyscallResult.Recvmsg doRecvmsg(int fd, Unix.Msghdr msg,
                                           int flags) throws IOException {
        String fmt = "recvmsg(fd=%d, msg=%s, flags=%d)";
        mLogger.info(String.format(fmt, fd, msg, flags));

        SyscallResult.Recvmsg result = new SyscallResult.Recvmsg();

        Socket socket;
        try {
            socket = getLockedSocket(fd);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            int len = 0;
            Unix.IoVec[] iov = msg.msg_iov;
            int iovlen = iov.length;
            for (int i = 0; i < iovlen; i++) {
                len += iov[i].iov_len;
            }
            byte[] buf = new byte[len];
            Unix.Cmsghdr[] control = msg.msg_control;
            result.retval = socket.recvmsg(buf, control);
            result.buf = buf;
            result.control = control;
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        finally {
            socket.unlock();
        }

        return result;
    }

    public SyscallResult.Generic64 doSendmsg(int fd, Unix.Msghdr msg,
                                             int flags) throws IOException {
        String fmt = "sendmsg(fd=%d, msg=%s, flags=%d)";
        mLogger.info(String.format(fmt, fd, msg, flags));

        SyscallResult.Generic64 result = new SyscallResult.Generic64();

        Socket socket;
        try {
            socket = getLockedSocket(fd);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            result.retval = socket.sendmsg(msg);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        finally {
            socket.unlock();
        }

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

        UnixFile file = getLockedFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
            mFcntlProcs.run(result, file, fd, cmd, arg);
        }
        finally {
            file.unlock();
        }

        return result;
    }

    public SyscallResult.Generic32 doClose(int fd) throws IOException {
        mLogger.info(String.format("close(fd=%d)", fd));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        synchronized (mFiles) {
            UnixFile file = getLockedFile(fd);
            if (file == null) {
                result.setError(Errno.EBADF);
                return result;
            }

            try {
                file.close();
            }
            catch (UnixException e) {
                result.setError(e.getErrno());
                return result;
            }
            finally {
                file.unlock();
            }

            mFiles[fd] = null;
        }

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
        result.retval = GID;
        return result;
    }

    public SyscallResult.Getresuid doGetresuid() throws IOException {
        mLogger.info("getresuid(*ruid, *euid, *suid)");
        SyscallResult.Getresuid result = new SyscallResult.Getresuid();

        result.ruid = result.euid = result.suid = UID;

        return result;
    }

    public SyscallResult.Getresgid doGetresgid() throws IOException {
        mLogger.info("getresgid(*rgid, *egid, *sgid)");
        SyscallResult.Getresgid result = new SyscallResult.Getresgid();

        result.rgid = result.egid = result.sgid = GID;

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
        if (fd == 2) {
            logPossibleDyingMessage(buf);
        }
        logBuffer(String.format("write: fd=%d: buf", fd), buf);

        SyscallResult.Generic64 result = new SyscallResult.Generic64();

        UnixFile file = getLockedFile(fd);
        if (file == null) {
            result.retval = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
            result.retval = file.write(buf);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        finally {
            file.unlock();
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
        Slave slave = mApplication.newSlave(pairId, mCurrentDirectory, files,
                                            mPermissions, mLinks, mListener,
                                            mAlarm);
        Pid pid = slave.getPid();
        Thread thread = new Thread(slave);
        thread.start();
        String fmt = "forked: thread=%s, pairId=%s, pid=%s";
        mLogger.info(String.format(fmt, thread.getName(), pairId, pid));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = pid.toInteger();

        return result;
    }

    public void doExit(int rval) throws IOException {
        mLogger.info(String.format("exit(rval=%d)", rval));
        mExitStatus = Integer.valueOf(rval);
    }

    public SyscallResult.Generic32 doChmod(String path,
                                           int mode) throws IOException {
        String fmt = "chmod(path=%s, mode=0o%o)";
        mLogger.info(String.format(fmt, StringUtil.quote(path), mode));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        NormalizedPath actPath = getActualPath(path);
        Object socket;
        try {
            socket = mApplication.getUnixDomainSocket(actPath);
        }
        catch (UnixException e) {
            socket = null;
        }
        if (socket != null) {
            return result;
        }

        if (!mPermissions.isAllowed(actPath)) {
            result.setError(Errno.EPERM);
            return result;
        }

        File file = new File(actPath.toString());
        if (!file.exists()) {
            result.setError(Errno.ENOENT);
            return result;
        }
        if (!changeMode(file, mode)) {
            result.setError(Errno.EPERM);
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doRmdir(String path) throws IOException {
        mLogger.info(String.format("rmdir(path=%s)", StringUtil.quote(path)));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        NormalizedPath actPath = getActualPath(path);
        if (!mPermissions.isAllowed(actPath)) {
            result.setError(Errno.EPERM);
            return result;
        }

        File file = new File(actPath.toString());
        if (!file.isDirectory()) {
            result.setError(file.exists() ? Errno.ENOTDIR : Errno.ENOENT);
            return result;
        }
        if (!file.delete()) {
            result.setError(Errno.EPERM);
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doUnlink(String path) throws IOException {
        mLogger.info(String.format("unlink(path=%s)", StringUtil.quote(path)));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        NormalizedPath actPath = getActualPath(path);
        try {
            mApplication.unlinkUnixDomainNode(actPath);
            return result;
        }
        catch (UnixException unused) {
            // nothing
        }

        if (!mPermissions.isAllowed(actPath)) {
            result.setError(Errno.EPERM);
            return result;
        }

        File file = new File(actPath.toString());
        if (!file.isFile()) {
            result.setError(file.exists() ? Errno.EISDIR : Errno.ENOENT);
            return result;
        }
        if (!file.delete()) {
            result.setError(Errno.EPERM);
            return result;
        }

        return result;
    }

    public SyscallResult.Generic32 doMkdir(String path,
                                           int mode) throws IOException {
        String fmt = "mkdir(path=%s, mode=0o%o)";
        mLogger.info(String.format(fmt, StringUtil.quote(path), mode));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        NormalizedPath actPath = getActualPath(path);
        if (!mPermissions.isAllowed(actPath)) {
            result.setError(Errno.EPERM);
            return result;
        }

        File file = new File(actPath.toString());
        if (!file.mkdir()) {
            result.setError(file.exists() ? Errno.EEXIST : Errno.EACCES);
            return result;
        }

        return result;
    }

    public SyscallResult.Wait4 doWait4(int pid, int options) throws IOException {
        mLogger.info(String.format("wait4(pid=%d, options=%d)", pid, options));
        SyscallResult.Wait4 result = new SyscallResult.Wait4();

        Slave slave;
        try {
            slave = mApplication.waitChildTerminating(new Pid(pid));
        }
        catch (InterruptedException unused) {
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

    public SyscallResult.Kevent doKevent(int kq, KEventArray changelist,
                                         int nchanges, int nevents,
                                         Unix.TimeSpec timeout) throws IOException {
        String fmt = "kevent(kq=%d, changelist=%s, nchanges=%d, nevents=%d, timeout=%s)";
        String msg = String.format(fmt, kq, changelist, nchanges, nevents,
                                   timeout);
        mLogger.info(msg);
        SyscallResult.Kevent retval = new SyscallResult.Kevent();

        UnixFile file = getLockedFile(kq);
        if (file == null) {
            retval.setError(Errno.EBADF);
            return retval;
        }
        try {
            KQueue kqueue;
            try {
                kqueue = (KQueue)file;
            }
            catch (ClassCastException unused) {
                retval.setError(Errno.EBADF);
                return retval;
            }
            Collection<KEvent> eventlist;
            try {
                eventlist = kqueue.kevent(changelist, nevents, timeout);
            }
            catch (UnixException e) {
                retval.setError(e.getErrno());
                return retval;
            }
            catch (InterruptedException unused) {
                retval.setError(Errno.EINTR);
                return retval;
            }
            retval.eventlist = eventlist.toArray(new KEvent[0]);
        }
        finally {
            file.unlock();
        }

        return retval;
    }

    private SyscallResult.Generic32 runPoll(PollReaction reaction,
                                            int timeout) throws IOException {
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        try {
            new AlarmReactor(reaction, timeout).run();
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        result.retval = reaction.getReadyFdsNumber();

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

    private UnixFile[] getFiles(Unix.Fdset fds) throws UnixException {
        int nfds = fds.size();
        int[] da = new int[nfds];
        for (int i = 0; i < nfds; i++) {
            da[i] = fds.get(i);
        }
        return getFiles(da);
    }

    private UnixFile[] getFiles(PollFds fds) throws UnixException {
        int nfds = fds.size();
        int[] da = new int[nfds];
        for (int i = 0; i < nfds; i++) {
            da[i] = fds.get(i).getFd();
        }
        return getFiles(da);
    }

    private UnixFile[] getFiles(int[] fds) throws UnixException {
        int nFiles = fds.length;
        UnixFile[] files = new UnixFile[nFiles];
        synchronized (mFiles) {
            for (int i = 0; i < nFiles; i++) {
                UnixFile file;
                try {
                    file = mFiles[fds[i]];
                }
                catch (IndexOutOfBoundsException e) {
                    throw new UnixException(Errno.EBADF, e);
                }
                if (file == null) {
                    throw new UnixException(Errno.EBADF);
                }
                files[i] = file;
            }
        }
        return files;
    }

    private UnixFile[] getLockedFiles(int[] fds) throws UnixException {
        UnixFile[] files = getFiles(fds);
        int nFiles = files.length;
        for (int i = 0; i < nFiles; i++) {
            files[i].lock();
        }
        return files;
    }

    /**
     * Returns a file of <var>fd</var> or null. A returned file is locked. You
     * M_U_S_T unlock this.
     */
    private UnixFile getLockedFile(int fd) {
        UnixFile file;
        synchronized (mFiles) {
            try {
                file = mFiles[fd];
            }
            catch (IndexOutOfBoundsException unused) {
                return null;
            }
        }
        if (file != null) {
            file.lock();
        }
        return file;
    }

    /**
     * Returns a file of <var>fd</var> or throws an exception. A returned file
     * is locked. You M_U_S_T unlock this.
     */
    private UnixFile getValidFile(int fd) throws UnixException {
        UnixFile file = getLockedFile(fd);
        if (file == null) {
            throw new UnixException(Errno.EBADF);
        }
        return file;
    }

    private void registerFileAt(UnixFile file, int at) {
        mFiles[at] = file;

        String fmt = "new file registered: file=%s, fd=%d";
        mLogger.info(String.format(fmt, file, at));
    }

    private int[] registerFiles(UnixFile[] files) throws UnixException {
        int nFiles = files.length;
        int[] fds = new int[nFiles];
        synchronized (mFiles) {
            for (int i = 0; i < nFiles; i++) {
                fds[i] = registerFile(files[i]);
            }
        }
        return fds;
    }

    private int registerFile(UnixFile file) throws UnixException {
        int fd;
        synchronized (mFiles) {
            fd = findFreeSlotOfFile();
            if (fd < 0) {
                throw new UnixException(Errno.EMFILE);
            }
            registerFileAt(file, fd);
        }
        return fd;
    }

    private int registerFile(FileRegisteringCallback callback) throws UnixException {
        int fd;
        synchronized (mFiles) {
            fd = findFreeSlotOfFile();
            if (fd < 0) {
                throw new UnixException(Errno.EMFILE);
            }
            registerFileAt(callback.call(), fd);
        }
        return fd;
    }

    private void registerFile(FileRegisteringCallback callback,
                              SyscallResult.Generic32 result) {
        int fd;
        try {
            fd = registerFile(callback);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return;
        }

        result.retval = fd;
    }

    private SyscallResult.Generic32 openActualFile(NormalizedPath absPath, int flags, int mode) throws IOException {
        mLogger.info(String.format("open actual file: %s", absPath));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (absPath.equals(mPwdDbPath)) {
            // This file is special.
            URL url = getClass().getResource("pwd.db");
            if (url == null) {
                result.setError(Errno.ENOENT);
                return result;
            }
            registerFile(new OpenResourceCallback(url), result);
            return result;
        }

        if (!mPermissions.isAllowed(absPath)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        registerFile(new OpenCallback(absPath, flags), result);
        return result;
    }

    private SyscallResult.Stat statActualFile(NormalizedPath absPath) throws IOException {
        mLogger.info(String.format("stat actual file: %s", absPath));

        SyscallResult.Stat result = new SyscallResult.Stat();

        if (!mPermissions.isAllowed(absPath)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        File file = new File(absPath.toString());
        long size;
        try {
            size = file.length();
        }
        catch (SecurityException e) {
            result.retval = -1;
            result.errno = Errno.EPERM;
            return result;
        }
        if ((size == 0L) && !file.isFile()) {
            result.setError(Errno.ENOENT);
            return result;
        }
        Unix.Stat stat = new Unix.Stat();
        stat.st_size = size;

        result.retval = 0;
        result.ub = stat;
        return result;
    }

    private SyscallResult.Readlink readlinkActualFile(NormalizedPath absPath,
                                                      long count)
                                                      throws IOException {
        mLogger.info(String.format("readlink actual file: %s", absPath));

        SyscallResult.Readlink result = new SyscallResult.Readlink();

        if (!mPermissions.isAllowed(absPath)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        result.retval = -1;
        result.errno = Errno.EINVAL;

        return result;
    }

    private SyscallResult.Generic32 accessActualFile(NormalizedPath absPath,
                                                     int flags)
                                                     throws IOException {
        mLogger.info(String.format("access actual file: %s", absPath));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (!mPermissions.isAllowed(absPath)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        result.retval = 0;
        return result;
    }

    private void logBuffer(String tag, byte[] buf, int len) {
        String s = ByteUtil.toString(buf, len);
        mLogger.debug(String.format("%s: %s", tag, s));
    }

    private void logBuffer(String tag, byte[] buf) {
        logBuffer(tag, buf, buf.length);
    }

    private void logPossibleDyingMessage(byte[] buf) {
        int size = Math.min(buf.length, 256);
        for (int i = 0; i < size; i++) {
            String fmt = "write(2) to fd 2: buf[%d]=0x%02x (%s)";
            byte c = buf[i];
            mLogger.debug(String.format(fmt, i, c, CHARS[c]));
        }
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

    /**
     * Returns a file of <var>fd</var> as a Socket. A returned socket is locked.
     * You M_U_S_T unlock this.
     */
    private Socket getLockedSocket(int fd) throws GetSocketException {
        UnixFile file = getLockedFile(fd);
        if (file == null) {
            throw new GetSocketException(Errno.EBADF);
        }
        Socket sock;
        try {
            sock = (Socket)file;
        }
        catch (ClassCastException unused) {
            file.unlock();
            throw new GetSocketException(Errno.ENOTSOCK);
        }
        return sock;
    }

    /*
    private File getFileUnderCurrentDirectory(String path) {
        return path.startsWith("/") ? new File(path)
                                    : new File(mCurrentDirectory, path);
    }

    private String getAbsolutePath(String path) throws IOException {
        return getFileUnderCurrentDirectory(path).getPath();
    }
    */

    private NormalizedPath getActualPath(String path) throws IOException {
        NormalizedPath normPath = new NormalizedPath(mCurrentDirectory, path);
        //String absPath = getAbsolutePath(path);
        return mLinks.get(normPath);
    }

    private SyscallResult.Generic32 runSetsockopt(int s, SocketLevel level,
                                                  SocketOption option,
                                                  int optval) {
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if ((level == null) || !level.equals(SocketLevel.SOL_SOCKET) || (option == null)) {
            result.setError(Errno.ENOPROTOOPT);
            return result;
        }

        Socket sock;
        try {
            sock = getLockedSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            if (optval != 0) {
                sock.addOption(option);
            }
            else {
                sock.removeOption(option);
            }
        }
        finally {
            sock.unlock();
        }

        return result;
    }

    private SyscallResult.Getsockopt runGetsockopt(int s, SocketLevel level,
                                                   SocketOption option) {
        SyscallResult.Getsockopt result = new SyscallResult.Getsockopt();

        Socket sock;
        try {
            sock = getLockedSocket(s);
        }
        catch (GetSocketException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            if (level.equals(SocketLevel.SOL_SOCKET)) {
                if (option.equals(SocketOption.SO_REUSEADDR)) {
                    result.optlen = 4;
                    result.n = sock.containsOption(option) ? option.intValue()
                                                           : 0;
                    return result;
                }
            }
        }
        finally {
            sock.unlock();
        }

        result.setError(Errno.ENOPROTOOPT);
        return result;
    }

    private boolean changeMode(File file, int mode) {
        if (!file.setReadable((Unix.Constants.S_IROTH & mode) != 0, false)) {
            return false;
        }
        if (!file.setReadable((Unix.Constants.S_IRUSR & mode) != 0)) {
            return false;
        }
        if (!file.setWritable((Unix.Constants.S_IWOTH & mode) != 0, false)) {
            return false;
        }
        if (!file.setWritable((Unix.Constants.S_IWUSR & mode) != 0)) {
            return false;
        }
        if (!file.setExecutable((Unix.Constants.S_IXOTH & mode) != 0, false)) {
            return false;
        }
        if (!file.setExecutable((Unix.Constants.S_IXUSR & mode) != 0)) {
            return false;
        }

        return true;
    }

    private void initialize(Application application, Pid pid, InputStream hubIn,
                            OutputStream hubOut,
                            NormalizedPath currentDirectory, UnixFile[] files,
                            Permissions permissions, Links links,
                            Listener listener, Alarm alarm) {
        mApplication = application;
        mPid = pid;
        mIn = new SyscallInputStream(hubIn);
        mOut = new SyscallOutputStream(hubOut);
        mPermissions = permissions;
        mLinks = links;
        setListener(listener);
        mCurrentDirectory = currentDirectory;
        mFiles = files;

        mAlarm = alarm;

        mHelper = new SlaveHelper(this, mIn, mOut);
        mFcntlProcs = new FcntlProcs();
        mFcntlProcs.put(Unix.Constants.F_GETFD, new FGetFdProc());
        mFcntlProcs.put(Unix.Constants.F_SETFD, new FSetFdProc());
        mFcntlProcs.put(Unix.Constants.F_SETFL, new FSetFlProc());
    }

    static {
        try {
            mPwdDbPath = new NormalizedPath("/etc/pwd.db");
        }
        catch (NormalizedPath.InvalidPathException unused) {
            // never works.
        }

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
