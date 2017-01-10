package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.Pipe;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.TimeZone;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.DirEntries;
import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;
import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.KEvent;
import jp.gr.java_conf.neko_daisuki.fsyscall.KEventArray;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.PairId;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.PollFd;
import jp.gr.java_conf.neko_daisuki.fsyscall.PollFds;
import jp.gr.java_conf.neko_daisuki.fsyscall.SigkillException;
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
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallReadableChannel;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallWritableChannel;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.ArrayUtil;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.ByteUtil;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.NormalizedPath;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.StringUtil;

/*
 * Android 3.2.1 does not have UnixSystem.
 */
//import com.sun.security.auth.module.UnixSystem;

/**
 * The class for one fsyscall thread.
 *
 * The Slave class must be public because the NexecClient is using the
 * Slave.Listener.
 */
public class Slave implements Runnable {

    public interface Listener {

        public static class NopListener implements Listener {

            public SocketCore onConnect(int domain, int type, int protocol,
                                        SocketAddress addr, Alarm alarm) {
                return null;
            }
        }

        public static final Listener NOP = new NopListener();

        public SocketCore onConnect(int domain, int type, int protocol,
                                    SocketAddress addr, Alarm alarm);
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
            while (!mDetector.isTimeout(t) && (act == TimeoutRunner.Action.CONTINUE) && !mTerminated) {
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

        public int getAccessMode() {
            return Unix.Constants.O_RDWR;
        }

        public boolean isReadyToRead() throws IOException {
            return false;
        }

        public boolean isReadyToWrite() throws IOException {
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

    private class OpenResourceCallback implements Process.FileRegisteringCallback {

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

    private class KQueueCallback implements Process.FileRegisteringCallback {

        public UnixFile call() throws UnixException {
            return new KQueue(mAlarm);
        }
    }

    private class SocketCallback implements Process.FileRegisteringCallback {

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

    private class OpenCallback implements Process.FileRegisteringCallback {

        private NormalizedPath mPath;
        private int mFlags;

        public OpenCallback(NormalizedPath path, int flags) {
            mPath = path;
            mFlags = flags;
        }

        public UnixFile call() throws UnixException {
            return new File(mPath.toString()).isDirectory() ? openDirectory()
                                                            : openRegularFile();
        }

        private UnixFile openDirectory() throws UnixException {
            int disallowedFlags = Unix.Constants.O_WRONLY
                                | Unix.Constants.O_RDWR;
            if ((mFlags & disallowedFlags) != 0) {
                throw new UnixException(Errno.EISDIR);
            }

            return new DirectoryFile(mAlarm, mPath);
        }

        private UnixFile openRegularFile() throws UnixException {
            if ((mFlags & Unix.Constants.O_DIRECTORY) != 0) {
                throw new UnixException(Errno.ENOTDIR);
            }
            int flags = Unix.Constants.O_CREAT | Unix.Constants.O_EXCL;
            String path = mPath.toString();
            if (((mFlags & flags) == flags) && new File(path).exists()) {
                throw new UnixException(Errno.EEXIST);
            }

            UnixFile file;
            switch (mFlags & Unix.Constants.O_ACCMODE) {
            case Unix.Constants.O_RDONLY:
                boolean create = (mFlags & Unix.Constants.O_CREAT) != 0;
                file = new UnixInputFile(mAlarm, path, create);
                break;
            case Unix.Constants.O_WRONLY:
                // XXX: Here ignores O_CREAT.
                file = new UnixOutputFile(mAlarm, path);
                break;
            case Unix.Constants.O_RDWR:
                file = new UnixInputOutputFile(mAlarm, path);
                break;
            default:
                throw new UnixException(Errno.EINVAL);
            }

            return file;
        }
    }

    private class AcceptCallback implements Process.FileRegisteringCallback {

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
            try {
                return file.isReadyToWrite();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
        }
    }

    private static class ReadSelectPred implements SelectPred {

        public boolean isReady(UnixFile file) throws UnixException {
            try {
                return file.isReadyToRead();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
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

            private class Connection {

                private boolean mClosed = false;

                public boolean isClosed() {
                    return mClosed;
                }

                public void close() {
                    mClosed = true;
                }
            }

            private Connection mConnection;
            private InputStream mIn;
            private OutputStream mOut;

            public PipeCore(Connection connection, Pair pair) {
                mConnection = connection;
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
                mConnection.close();
                mIn.close();
                mOut.close();
            }

            @Override
            public boolean isDisconnected() {
                return mConnection.isClosed();
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

            @Override
            public boolean isDisconnected() {
                return false;
            }
        }

        private class ControlBuffer {

            public class Writer {

                public void write(Control control) throws InterruptedException {
                    synchronized (mQueue) {
                        mQueue.offer(control);
                    }
                }
            }

            public class Reader {

                public Control read() throws InterruptedException {
                    synchronized (mQueue) {
                        return mQueue.poll();
                    }
                }
            }

            private Queue<Control> mQueue;
            private Reader mReader = new Reader();
            private Writer mWriter = new Writer();

            public ControlBuffer() {
                mQueue = new LinkedList<Control>();
            }

            public Reader getReader() {
                return mReader;
            }

            public Writer getWriter() {
                return mWriter;
            }
        }

        private class ConnectingRequest {

            private class Connection {

                private boolean mClosed = false;

                public boolean isClosed() {
                    return mClosed;
                }

                public void close() {
                    mClosed = true;
                }
            }

            private class PipeCore implements SocketCore {

                private Connection mConnection;
                private InputStream mIn;
                private OutputStream mOut;

                public PipeCore(Connection connection, InputStream in,
                                OutputStream out) {
                    mConnection = connection;
                    mIn = in;
                    mOut = out;
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
                    mConnection.close();
                    mIn.close();
                    mOut.close();
                }

                @Override
                public boolean isDisconnected() {
                    return mConnection.isClosed();
                }
            }

            private boolean mAccepted = false;
            private Socket mPeer;
            private SocketCore mClientCore;
            private SocketCore mServerCore;
            private ControlBuffer mControlBufferFromClient;
            private ControlBuffer mControlBufferFromServer;

            public ConnectingRequest(Socket peer) throws UnixException {
                mPeer = peer;

                Connection connection = new Connection();
                jp.gr.java_conf.neko_daisuki.fsyscall.io.Pipe s2c = new jp.gr.java_conf.neko_daisuki.fsyscall.io.Pipe();
                jp.gr.java_conf.neko_daisuki.fsyscall.io.Pipe c2s = new jp.gr.java_conf.neko_daisuki.fsyscall.io.Pipe();
                mClientCore = new PipeCore(connection, s2c.getInputStream(),
                                           c2s.getOutputStream());
                mServerCore = new PipeCore(connection, c2s.getInputStream(),
                                           s2c.getOutputStream());

                mControlBufferFromClient = new ControlBuffer();
                mControlBufferFromServer = new ControlBuffer();
            }

            public SocketCore getClientCore() {
                return mClientCore;
            }

            public SocketCore getServerCore() {
                return mServerCore;
            }

            public Socket getPeer() {
                return mPeer;
            }

            public void accept() {
                mAccepted = true;
            }

            public boolean isAccepted() {
                return mAccepted;
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
        private boolean mShutdownRead = false;
        private boolean mShutdownWrite = false;

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

        public int getAccessMode() {
            return Unix.Constants.O_RDWR;
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

        public void setExternalCore(SocketCore core) {
            setCore(core);
            ControlBuffer buf = new ControlBuffer();
            mControlReader = buf.getReader();
            mControlWriter = buf.getWriter();
        }

        public boolean isReadyToRead() throws IOException {
            if (mConnectingRequests != null) {
                synchronized (mConnectingRequests) {
                    return !mConnectingRequests.isEmpty();
                }
            }

            SocketCore core;
            try {
                core = getCore();
            }
            catch (UnixException unused) {
                /*
                 * poll(2) for a socket which has not been connected yet returns
                 * nothing (It does not return POLLERR nor EIO).
                 */
                return false;
            }
            InputStream in = core.getInputStream();
            if (in == null) {
                return false;
            }
            try {
                return 0 < in.available();
            }
            catch (IOException unused) {
                return false;
            }
        }

        public boolean isReadyToWrite() throws IOException {
            return !isDisconnected();
        }

        public boolean isDisconnected() {
            return mCore != null ? mCore.isDisconnected() : false;
        }

        public int read(byte[] buffer) throws UnixException {
            if (mShutdownRead) {
                return 0;
            }

            try {
                if (isNonBlocking() && !isReadyToRead()) {
                    throw new UnixException(Errno.EAGAIN);
                }
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            InputStream in = getCore().getInputStream();
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
            if (mShutdownRead) {
                return 0L;
            }

            int len = buffer.length;
            InputStream in = getCore().getInputStream();
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
            Unix.Stat st = new Unix.Stat(UID, GID);
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
            setCore(request.getClientCore());
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

            Socket peer = request.getPeer();
            peer.setPeer(this);
            request.accept();
            synchronized (request) {
                request.notifyAll();
            }

            Socket socket = new Socket(getAlarm(), mDomain, mType, mProtocol,
                                       mName, peer);
            socket.setCore(request.getServerCore());
            socket.mControlReader = request.getControlBufferFromClient().getReader();
            socket.mControlWriter = request.getControlBufferFromServer().getWriter();

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
                Unix.Cmsghdr cmsghdr;
                if (cntl != null) {
                    cmsghdr = cntl.getCmsghdr();
                    switch (cmsghdr.cmsg_level) {
                    case Unix.Constants.SOL_SOCKET:
                        switch (cmsghdr.cmsg_type) {
                        case Unix.Constants.SCM_CREDS:
                            break;
                        case Unix.Constants.SCM_RIGHTS:
                            int[] fds = mProcess.registerFiles(cntl.getFiles());
                            cmsghdr.cmsg_data = new Unix.Cmsgfds(fds);
                            break;
                        default:
                            break;
                        }
                        break;
                    default:
                        break;
                    }
                }
                else {
                    cmsghdr = null;
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

        public void shutdown(Unix.Constants.Shutdown.How how) throws UnixException {
            if (mCore == null) {
                throw new UnixException(Errno.ENOTCONN);
            }

            if (Unix.Constants.Shutdown.How.SHUT_RD.equals(how)) {
                mShutdownRead = true;
            }
            else if (Unix.Constants.Shutdown.How.SHUT_WR.equals(how)) {
                mShutdownWrite = true;
            }
            else if (Unix.Constants.Shutdown.How.SHUT_RDWR.equals(how)) {
                mShutdownRead = mShutdownWrite = true;
            }
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
            if (mShutdownWrite) {
                throw new UnixException(Errno.EPIPE);
            }

            OutputStream out = getCore().getOutputStream();
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
            // Closing a disconnected socket is valid.
            if (mCore == null) {
                return;
            }
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
            UnixFile[] files = mProcess.getLockedFiles(fds);
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
            Pid pid = getPid();
            Unix.Cmsgdata data = new Unix.Cmsgcred(pid, UID, UID, GID, groups);
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

        private SocketCore getCore() throws UnixException {
            if (mCore == null) {
                throw new UnixException(Errno.ENOTCONN);
            }
            return mCore;
        }
    }

    private class ExternalPeer extends Socket {

        public ExternalPeer(Alarm alarm, int domain, int type, int protocol,
                            SocketAddress name, Socket peer) {
            super(alarm, domain, type, protocol, name, peer);
        }
    }

    private static class RandomAccessFileUtil {

        public static int read(RandomAccessFile file,
                               byte[] buffer) throws UnixException {
            int nBytes;
            try {
                nBytes = file.read(buffer);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return nBytes != -1 ? nBytes : 0;
        }

        public static long pread(RandomAccessFile file, byte[] buffer,
                                 long offset) throws UnixException {
            int nBytes;
            try {
                long initialPosition = file.getFilePointer();
                file.seek(offset);
                try {
                    nBytes = file.read(buffer);
                }
                finally {
                    file.seek(initialPosition);
                }
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            return nBytes == -1 ? 0 : nBytes;
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
            Unix.Stat st = new Unix.Stat(UID, GID);

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

    private class DirectoryFile extends UnixFile {

        private List<Unix.DirEnt> mEntries;
        private int mPosition;
        private NormalizedPath mPath;

        public DirectoryFile(Alarm alarm,
                             NormalizedPath path) throws UnixException {
            super(alarm);

            mEntries = new ArrayList<Unix.DirEnt>();
            mEntries.add(new Unix.DirEnt(Unix.Constants.DT_DIR, "."));
            mEntries.add(new Unix.DirEnt(Unix.Constants.DT_DIR, ".."));

            File[] files = path.toFile().listFiles();
            if (files == null) {
                throw new UnixException(Errno.ENOENT);
            }
            int nFiles = files.length;
            for (int i = 0; i < nFiles; i++) {
                File file = files[i];
                int type = file.isFile() ? Unix.Constants.DT_REG
                                         : Unix.Constants.DT_DIR;
                mEntries.add(new Unix.DirEnt(type, file.getName()));
            }

            mPath = path;
        }

        public NormalizedPath getPath() {
            return mPath;
        }

        /**
         * In my investigation, poll(2) for a directory returns POLLIN/POLLOUT
         * always.
         */
        public boolean isReadyToRead() throws IOException {
            return true;
        }

        /**
         * In my investigation, poll(2) for a directory returns POLLIN/POLLOUT
         * always.
         */
        public boolean isReadyToWrite() throws IOException {
            return true;
        }

        public int getAccessMode() {
            return Unix.Constants.O_RDONLY;
        }

        public DirEntries getdirentries(int nMax) throws UnixException {
            List<Unix.DirEnt> l = new ArrayList<Unix.DirEnt>();

            int n = Math.min(mEntries.size() - mPosition, nMax);
            for (int i = 0; i < n; i++) {
                l.add(mEntries.get(mPosition + i));
            }
            mPosition += n;

            return new DirEntries(l);
        }

        public int read(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EISDIR);
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            throw new UnixException(Errno.EISDIR);
        }

        public long lseek(long offset, int whence) throws UnixException {
            // nothing?
            return 0L;
        }

        public Unix.Stat fstat() throws UnixException {
            Unix.Stat st = new Unix.Stat(UID, GID);
            st.st_mode = Unix.Constants.S_IRWXU
                       | Unix.Constants.S_IRGRP
                       | Unix.Constants.S_IXGRP
                       | Unix.Constants.S_IROTH
                       | Unix.Constants.S_IXOTH
                       | Unix.Constants.S_IFDIR;
            return st;
        }

        public long getFilterFlags() {
            // TODO?
            return 0L;
        }

        public void clearFilterFlags() {
            // nothing?
        }

        protected void doClose() throws UnixException {
            // nothing
        }

        protected int doWrite(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }
    }

    private static class UnixInputFile extends UnixRandomAccessFile {

        public UnixInputFile(Alarm alarm, String path,
                             boolean create) throws UnixException {
            super(alarm, path, create ? "rw" : "r");
        }

        public int getAccessMode() {
            return Unix.Constants.O_RDONLY;
        }

        public boolean isReadyToRead() throws IOException {
            return true;
        }

        public boolean isReadyToWrite() throws IOException {
            return false;
        }

        public int read(byte[] buffer) throws UnixException {
            return RandomAccessFileUtil.read(mFile, buffer);
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            return RandomAccessFileUtil.pread(mFile, buffer, offset);
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

        public int getAccessMode() {
            return Unix.Constants.O_WRONLY;
        }

        public boolean isReadyToRead() throws IOException {
            return false;
        }

        public boolean isReadyToWrite() throws IOException {
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

    private static class UnixInputOutputFile extends UnixRandomAccessFile {

        private long mFilterFlags;

        public UnixInputOutputFile(Alarm alarm,
                                   String path) throws UnixException {
            super(alarm, path, "rw");
        }

        public int getAccessMode() {
            return Unix.Constants.O_RDWR;
        }

        public boolean isReadyToRead() throws IOException {
            return true;
        }

        public boolean isReadyToWrite() throws IOException {
            return true;
        }

        public int read(byte[] buffer) throws UnixException {
            return RandomAccessFileUtil.read(mFile, buffer);
        }

        public long pread(byte[] buffer, long offset) throws UnixException {
            return RandomAccessFileUtil.pread(mFile, buffer, offset);
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

        public int getAccessMode() {
            return Unix.Constants.O_RDONLY;
        }

        public boolean isReadyToRead() throws IOException {
            try {
                return 0 < mIn.available();
            }
            catch (IOException unused) {
                return false;
            }
        }

        public boolean isReadyToWrite() throws IOException {
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

        public int getAccessMode() {
            return Unix.Constants.O_WRONLY;
        }

        public boolean isReadyToRead() throws IOException {
            return false;
        }

        public boolean isReadyToWrite() throws IOException {
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

    private class FGetFlProc implements FcntlProc {

        public void run(SyscallResult.Generic32 result, UnixFile file, int fd,
                        int cmd, long arg) {
            int accMode = file.getAccessMode();
            accMode |= file.isNonBlocking() ? Unix.Constants.O_NONBLOCK : 0;
            result.retval = accMode;
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
            this(reaction);

            if (timeout != Unix.Constants.INFTIM) {
                int sec = (int)(timeout / 1000);
                long nsec = (timeout % 1000) * 1000000;
                mTimeout = new Unix.TimeSpec(sec, nsec);
            }
        }

        public AlarmReactor(AlarmReaction reaction, Unix.TimeVal timeout) {
            this(reaction);

            if (timeout != null) {
                int sec = (int)timeout.tv_sec;
                long nsec = 1000 * timeout.tv_usec;
                mTimeout = new Unix.TimeSpec(sec, nsec);
            }
        }

        public AlarmReactor(AlarmReaction reaction) {
            mReaction = reaction;
        }

        public void run() throws IOException, SigkillException, UnixException {
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
                    if (mPendingSignals.contains(Signal.SIGKILL)) {
                        throw new SigkillException();
                    }
                    if (mTerminated) {
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
    }

    private class Wait4Reaction implements AlarmReaction {

        private Pid mPid;

        public Wait4Reaction(Pid pid) {
            mPid = pid;
        }

        public int run() throws UnixException {
            boolean terminated = mApplication.pollChildTermination(mPid);
            return terminated ? AlarmReactor.ACTION_BREAK
                              : AlarmReactor.ACTION_CONTINUE;
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
                    if (file.isDisconnected()) {
                        fd.addRevents(Unix.Constants.POLLHUP);
                    }
                }
                catch (IOException unused) {
                    fd.addRevents(Unix.Constants.POLLERR);
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

    private enum SelectionKeyType {
        HUB,
        SIGNAL
    }

    private static final int UID = 1001;
    private static final int GID = 1001;
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

    private final Process.FileRegisteringCallback KQUEUE_CALLBACK = new KQueueCallback();

    // settings
    private Application mApplication;
    private SyscallReadableChannel mIn;
    private SyscallWritableChannel mOut;
    private Permissions mPermissions;
    private Links mLinks;
    private Listener mListener;

    // states
    private Process mProcess;
    private NormalizedPath mCurrentDirectory;
    private SignalSet mPendingSignals = new SignalSet();

    private Alarm mAlarm;
    private Object mSignalNotificationLock = new Object();
    private Pipe.SourceChannel mSignalNotificationSource;
    private Pipe.SinkChannel mSignalNotificationSink;

    // helpers
    private SlaveHelper mHelper;
    private FcntlProcs mFcntlProcs;
    private boolean mTerminated = false;
    private EventFilters mEventFilters = new EventFilters();
    private ByteBuffer mSignalNotification;

    public Slave(Application application, Process process,
                 SyscallReadableChannel hubIn, SyscallWritableChannel hubOut,
                 NormalizedPath currentDirectory, InputStream stdin,
                 OutputStream stdout, OutputStream stderr,
                 Permissions permissions, Links links, Listener listener) throws IOException {
        mLogger.info("a slave is starting.");

        initialize(application, process, hubIn, hubOut, currentDirectory,
                   permissions, links, listener);

        mProcess.registerFileAt(new UnixInputStream(mAlarm, stdin), 0);
        mProcess.registerFileAt(new UnixOutputStream(mAlarm, stdout), 1);
        mProcess.registerFileAt(new UnixOutputStream(mAlarm, stderr), 2);

        writeOpenedFileDescriptors();
        mLogger.verbose("file descripters were transfered from the slave.");
    }

    /**
     * Constructor for fork(2)/thr_new(2).
     */
    public Slave(Application application, Process process,
                 SyscallReadableChannel hubIn, SyscallWritableChannel hubOut,
                 NormalizedPath currentDirectory, Permissions permissions,
                 Links links, Listener listener) throws IOException {
        initialize(application, process, hubIn, hubOut, currentDirectory,
                   permissions, links, listener);
    }

    public void kill(Signal sig) throws UnixException {
        if (sig == null) {
            throw new UnixException(Errno.EINVAL);
        }
        synchronized (mSignalNotificationLock) {
            mPendingSignals.add(sig);
            mSignalNotification.rewind();
            int nBytes;
            try {
                nBytes = mSignalNotificationSink.write(mSignalNotification);
            }
            catch (IOException e) {
                throw new UnixException(Errno.EIO, e);
            }
            if (nBytes != mSignalNotification.capacity()) {
                String fmt = "cannot write signal notification: %d[bytes]";
                throw new Error(String.format(fmt, nBytes));
            }
        }
        mAlarm.alarm();
    }

    @Override
    public void run() {
        mLogger.info("a slave started: pid=%s", getPid());

        try {
            Selector selector = Selector.open();
            mIn.register(selector, SelectionKeyType.HUB);
            mSignalNotificationSource.configureBlocking(false);
            mSignalNotificationSource.register(selector, SelectionKey.OP_READ,
                                               SelectionKeyType.SIGNAL);

            try {
                try {
                    while (!mTerminated) {
                        try {
                            doIterationWork(selector);
                        }
                        catch (SigkillException e) {
                            Signal sig = Signal.SIGKILL;
                            writeSignaled(sig);
                            mProcess.setExitCode(sig);
                            terminate();
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
            mLogger.err(e, "I/O error");
            e.printStackTrace();
        }
        mProcess.remove(this);
        mApplication.onSlaveTerminated(mProcess);
    }

    public void terminate() {
        mTerminated = true;
        mAlarm.alarm();
    }

    public Pid getPid() {
        return mProcess.getPid();
    }

    public SyscallResult.Generic32 doSigprocmask(int how, SignalSet set) {
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
        mLogger.info("sigprocmask(how=%d (%s), set=%s)", how, howString, set);

        return new SyscallResult.Generic32();
    }

    public SyscallResult.Generic32 doKill(int pid, int signum) throws IOException {
        String fmt = "kill(pid=%d, signum=%d (%s))";
        mLogger.info(fmt, pid, signum, Signal.toString(signum));

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
        mLogger.info("listen(s=%d, backlog=%d)", s, backlog);
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
        mLogger.info("chdir(path=%s)", StringUtil.quote(path));
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
        mLogger.info("open(path=%s, flags=0x%x (%s), mode=0o%o (%s))",
                     StringUtil.quote(path),
                     flags, Unix.Constants.Open.toString(flags), mode,
                     Unix.Constants.Mode.toString(mode));

        if (path.equals("/etc/pwd.db")) {
            // This file is special.
            SyscallResult.Generic32 result = new SyscallResult.Generic32();
            URL url = getClass().getResource("pwd.db");
            if (url == null) {
                result.setError(Errno.ENOENT);
                return result;
            }
            if ((flags & Unix.Constants.O_DIRECTORY) != 0) {
                result.setError(Errno.ENOTDIR);
                return result;
            }
            registerFile(new OpenResourceCallback(url), result);
            return result;
        }

        return openActualFile(getActualPath(path), flags, mode);
    }

    public SyscallResult.Generic32 doOpenat(int fd, String path, int flags,
                                            int mode) throws IOException {
        mLogger.info("openat(fd=%d, path=%s, flags=0o%o (%s), mode=0o%o (%s))",
                     fd, StringUtil.quote(path), flags,
                     Unix.Constants.Open.toString(flags), mode,
                     Unix.Constants.Mode.toString(mode));
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (path.startsWith("/")) {
            // If the path is absolute, openat(2) ignores the fd.
            return openActualFile(getActualPath(path), flags, mode);
        }

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            DirectoryFile dir;
            try {
                dir = (DirectoryFile)file;
            }
            catch (ClassCastException unused) {
                result.setError(Errno.EINVAL);
                return result;
            }
            NormalizedPath absPath = new NormalizedPath(dir.getPath(), path);
            return openActualFile(absPath, flags, mode);
        }
        finally {
            file.unlock();
        }
    }

    public SyscallResult.Read doRead(int fd, long nbytes) throws IOException {
        mLogger.info("read(fd=%d, nbytes=%d)", fd, nbytes);
        SyscallResult.Read result = new SyscallResult.Read();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
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
        mLogger.info("lseek(fd=%d, offset=%d, whence=%d)", fd, offset, whence);

        SyscallResult.Generic64 result = new SyscallResult.Generic64();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
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
        mLogger.info("pread(fd=%d, nbyte=%d, offset=%d)", fd, nbyte, offset);

        SyscallResult.Pread result = new SyscallResult.Pread();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
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
        mLogger.info("getpeername(s=%d, namelen=%d)", s, namelen);
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
        mLogger.info("getsockname(s=%d, namelen=%d)", s, namelen);
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

    public SyscallResult.Accept doAccept4(int s, int addrlen, int flags) throws IOException {
        mLogger.info("accept4(s=%d, addrlen=%d, flags=0x%x (%s))",
                     s, addrlen, flags, Unix.Constants.Socket.toString(flags));

        SyscallResult.Accept result = doAccept(s, addrlen);
        if ((flags == 0) || (result.retval == -1)) {
            return result;
        }

        UnixFile file;
        try {
            file = mProcess.getLockedFile(result.retval);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            file.setCloseOnExec((flags & Unix.Constants.SOCK_CLOEXEC) != 0);
            file.enableNonBlocking((flags & Unix.Constants.SOCK_NONBLOCK) != 0);
        }
        finally {
            file.unlock();
        }

        return result;
    }

    public SyscallResult.Accept doAccept(int s, int addrlen) throws IOException {
        mLogger.info("accept(s=%d, addrlen=%d)", s, addrlen);
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
                fd = mProcess.registerFile(callback);
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

    public SyscallResult.Generic32 doFsync(int fd) {
        mLogger.info("fsync(fd=%d)", fd);
        // does nothing.
        return new SyscallResult.Generic32();
    }

    public SyscallResult.Generic32 doRename(String from,
                                            String to) throws IOException {
        mLogger.info("rename(from=%s, to=%s)",
                     StringUtil.quote(from), StringUtil.quote(to));
        return renameActualFile(getActualPath(from), getActualPath(to));
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
        mLogger.info("lstat(path=%s)", StringUtil.quote(path));

        SyscallResult.Lstat result = new SyscallResult.Lstat();

        SyscallResult.Stat statResult = doStat(path);
        result.retval = statResult.retval;
        result.errno = statResult.errno;
        result.ub = statResult.ub;

        return result;
    }

    public SyscallResult.Fstat doFstat(int fd) throws IOException {
        mLogger.info("fstat(fd=%d)", fd);

        SyscallResult.Fstat result = new SyscallResult.Fstat();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
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
        mLogger.info("stat(path=%s)", StringUtil.quote(path));
        return statActualFile(getActualPath(path));
    }

    public SyscallResult.Generic32 doBind(int s, UnixDomainAddress addr,
                                          int addrlen) throws IOException {
        mLogger.info("bind(s=%d, addr=%s, addrlen=%d)", s, addr, addrlen);
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
        mLogger.info(fmt,
                     "setsockopt", s, level, levelName, optname, name, optlen,
                     optval);

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
        mLogger.info(fmt, s, level, levelName, optname, name, optlen);

        return runGetsockopt(s, SocketLevel.valueOf(level),
                             SocketOption.valueOf(optname));
    }

    public SyscallResult.Generic32 doShutdown(int s, int how) {
        Unix.Constants.Shutdown.How h;
        h = Unix.Constants.Shutdown.How.valueOf(how);
        String fmt = "shutdown(s=%d, how=%d (%s))";
        mLogger.info(fmt, s, how, h != null ? h : "invalid");
        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        if (h == null) {
            result.setError(Errno.EINVAL);
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
            sock.shutdown(h);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
        }
        finally {
            sock.unlock();
        }

        return result;
    }

    public SyscallResult.Generic32 doConnect(int s, UnixDomainAddress name,
                                             int namelen) throws IOException {
        mLogger.info("connect(s=%d, name=%s, namelen=%d)", s, name, namelen);
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
            SocketCore core = mListener.onConnect(domain, type, protocol, name,
                                                  mAlarm);
            if (core == null) {
                result.setError(err);
                return result;
            }
            sock.setExternalCore(core);
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
        mLogger.info("writev(fd=%d, iovec=%s)", fd, ArrayUtil.toString(iovec));

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
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
        mLogger.info(fmt, domain, type, protocol);
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        Process.FileRegisteringCallback callback = new SocketCallback(domain,
                                                                      type,
                                                                      protocol);
        registerFile(callback, result);

        return result;
    }

    public SyscallResult.Generic32 doPollStart(PollFds fds, int nfds, int timeout) throws IOException, SigkillException {
        String fmt = "interruptable poll(fds=%s, nfds=%d, timeout=%d)";
        mLogger.info(fmt, fds, nfds, timeout);

        UnixFile[] files;
        try {
            files = mProcess.getFiles(fds);
        }
        catch (UnixException e) {
            return new SyscallResult.Generic32(e.getErrno());
        }

        return runPoll(new InterruptablePollReaction(fds, files), timeout);
    }

    public SyscallResult.Generic32 doPoll(PollFds fds, int nfds, int timeout) throws IOException, SigkillException {
        mLogger.info("poll(fds=%s, nfds=%d, timeout=%d)", fds, nfds, timeout);

        UnixFile[] files;
        try {
            files = mProcess.getFiles(fds);
        }
        catch (UnixException e) {
            return new SyscallResult.Generic32(e.getErrno());
        }

        return runPoll(new PollReaction(fds, files), timeout);
    }

    public SyscallResult.Select doSelect(Unix.Fdset in, Unix.Fdset ou,
                                         Unix.Fdset ex, Unix.TimeVal timeout) throws IOException, SigkillException {
        String fmt = "select(in=%s, ou=%s, ex=%s, timeout=%s)";
        mLogger.info(fmt, in, ou, ex, timeout);
        SyscallResult.Select result = new SyscallResult.Select();

        Process.SelectFiles files;
        try {
            files = mProcess.getFiles(in, ou, ex);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        UnixFile[] inFiles = files.inFiles;
        UnixFile[] ouFiles = files.ouFiles;
        UnixFile[] exFiles = files.exFiles;

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
        mLogger.info(fmt, StringUtil.quote(path), count);

        return readlinkActualFile(getActualPath(path), count);
    }

    /**
     * The dummy implementation of access(2).
     */
    public SyscallResult.Generic32 doAccess(String path, int flags) throws IOException {
        String fmt = "access(path=%s, flags=0x%02x)";
        mLogger.info(fmt, StringUtil.quote(path), flags);

        return accessActualFile(getActualPath(path), flags);
    }

    public SyscallResult.Generic32 doLink(String path1, String path2) throws IOException {
        String s1 = StringUtil.quote(path1);
        String s2 = StringUtil.quote(path2);
        mLogger.info("link(path1=%s, path2=%s)", s1, s2);

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = -1;
        result.errno = Errno.ENOSYS;
        return result;
    }

    public SyscallResult.Recvmsg doRecvmsg(int fd, Unix.Msghdr msg,
                                           int flags) throws IOException {
        mLogger.info("recvmsg(fd=%d, msg=%s, flags=%d)", fd, msg, flags);

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
        mLogger.info("sendmsg(fd=%d, msg=%s, flags=%d)", fd, msg, flags);
        log("sendmsg", "msg.msg_iov", msg.msg_iov);

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
        mLogger.info(fmt, fd, cmd, name, arg, s);
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
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
        mLogger.info("close(fd=%d)", fd);
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        try {
            mProcess.closeFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
        }

        return result;
    }

    public SyscallResult.Getdirentries doGetdirentries(int fd, int nMax) throws IOException {
        mLogger.info("getdirentries(fd=%d, nMax=%d)", fd, nMax);
        SyscallResult.Getdirentries result = new SyscallResult.Getdirentries();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        try {
            result.dirEntries = file.getdirentries(nMax);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }
        finally {
            file.unlock();
        }

        result.retval = 1;

        return result;
    }

    public SyscallResult.Generic32 doUtimes(String path, Unix.TimeVal[] times) throws IOException {
        String fmt = "utimes(path=%s, times=%s)";
        mLogger.info(fmt, StringUtil.quote(path), ArrayUtil.toString(times));
        // does nothing.
        return new SyscallResult.Generic32();
    }

    public SyscallResult.Generic32 doUmask(int newmask) throws IOException {
        mLogger.info("umask(newmask=0o%o)", newmask);
        return new SyscallResult.Generic32(022);
    }

    /**
     * Fake implementation of getpid(2). Java does not have any compatible ways
     * to getpid(2). So this method returns the dummy value.
     */
    public SyscallResult.Generic32 doGetpid() throws IOException {
        mLogger.info("getpid()");
        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = getPid().toInteger();
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
        mLogger.info("write(fd=%d, buf, nbytes=%d)", fd, nbytes);
        /*
        if (fd == 2) {
            logPossibleDyingMessage(buf);
        }
        */
        logBuffer(String.format("write: fd=%d: buf", fd), buf);

        SyscallResult.Generic64 result = new SyscallResult.Generic64();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
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

    public SyscallResult.Generic32 doThrNew(PairId newPairId) throws IOException {
        mLogger.info("thr_new(newPairId=%s)", newPairId);

        Slave slave = mApplication.newSlave(newPairId, mProcess,
                                            mCurrentDirectory, mPermissions,
                                            mLinks, mListener);
        startSlave(slave, "thr_new(2)'ed", newPairId);

        return new SyscallResult.Generic32();
    }

    public SyscallResult.Generic32 doFork(PairId pairId) throws IOException {
        mLogger.info("fork(pairId=%s)", pairId);

        Slave slave = mApplication.newProcess(pairId, mProcess,
                                              mCurrentDirectory, mPermissions,
                                              mLinks, mListener);
        startSlave(slave, "forked", pairId);

        SyscallResult.Generic32 result = new SyscallResult.Generic32();
        result.retval = slave.getPid().toInteger();

        return result;
    }

    public void doThrExit() throws IOException {
        mLogger.info("thr_exit()");

        if (mProcess.size() == 1) {
            return;
        }

        terminate();
    }

    public void doExit(int rval) throws IOException {
        mLogger.info("exit(rval=%d)", rval);
        mProcess.setExitCode(rval);
        terminate();
    }

    public SyscallResult.Generic32 doChmod(String path,
                                           int mode) throws IOException {
        mLogger.info("chmod(path=%s, mode=0o%o)", StringUtil.quote(path), mode);
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
        mLogger.info("rmdir(path=%s)", StringUtil.quote(path));
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
        mLogger.info("unlink(path=%s)", StringUtil.quote(path));
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
        mLogger.info("mkdir(path=%s, mode=0o%o)", StringUtil.quote(path), mode);
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

    public SyscallResult.Wait4 doWait4(int pid,
                                       int options) throws IOException,
                                                           SigkillException {
        String fmt = "wait4(pid=%d, options=%d (%s))";
        mLogger.info(fmt, pid, options, Unix.Constants.Wait4.toString(options));

        Process process = mProcess.findChild(new Pid(pid));
        if (process == null) {
            SyscallResult.Wait4 result = new SyscallResult.Wait4();
            result.setError(Errno.ECHILD);
            return result;
        }

        return ((options & Unix.Constants.WNOHANG) == 0) ? doWait4(process)
                                                         : doWait4NoHang(process);
    }

    public SyscallResult.Kevent doKevent(int kq, KEventArray changelist,
                                         int nchanges, int nevents,
                                         Unix.TimeSpec timeout) throws IOException {
        String fmt = "kevent(kq=%d, changelist=%s, nchanges=%d, nevents=%d, timeout=%s)";
        mLogger.info(fmt, kq, changelist, nchanges, nevents, timeout);
        SyscallResult.Kevent retval = new SyscallResult.Kevent();

        UnixFile file;
        try {
            file = mProcess.getLockedFile(kq);
        }
        catch (UnixException e) {
            retval.setError(e.getErrno());
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

    private void doIterationWork(Selector selector) throws IOException,
                                                           SigkillException {
        int nChannels = selector.select(120 * 1000);    // [msec]
        switch (nChannels) {
        case 0:
            throw new IOException("timeout");
        case 1:
        case 2:
            break;
        default:
            String fmt = "Selector.select() returned invalid value, %d";
            throw new Error(String.format(fmt, nChannels));
        }

        Set<SelectionKey> keys = selector.selectedKeys();
        for (SelectionKey key: keys) {
            SelectionKeyType a = (SelectionKeyType)key.attachment();
            switch (a) {
            case HUB:
                mHelper.runSlave();
                break;
            case SIGNAL:
                synchronized (mSignalNotificationLock) {
                    ByteBuffer buffer = ByteBuffer.allocate(32);
                    while (0 < mSignalNotificationSource.read(buffer)) {
                    }

                    if (mPendingSignals.contains(Signal.SIGKILL)) {
                        throw new SigkillException();
                    }
                    for (Signal sig: mPendingSignals.toCollection()) {
                        writeSignaled(sig);
                    }
                }
                break;
            default:
                String fmt = "invalid attachment type: %s";
                throw new Error(String.format(fmt, a));
            }
        }
        keys.clear();
    }

    private SyscallResult.Wait4 doWait4NoHang(Process process) {
        SyscallResult.Wait4 result = new SyscallResult.Wait4();

        Pid pid = process.getPid();
        try {
            if (mApplication.pollChildTermination(pid)) {
                result.retval = pid.toInteger();
                result.status = process.getExitCode();
            }
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        result.rusage = new Unix.Rusage();

        return result;
    }

    private SyscallResult.Wait4 doWait4(Process process) throws IOException,
                                                                SigkillException {
        SyscallResult.Wait4 result = new SyscallResult.Wait4();

        Pid pid = process.getPid();
        try {
            new AlarmReactor(new Wait4Reaction(pid)).run();
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return result;
        }

        result.retval = pid.toInteger();
        result.status = process.getExitCode();
        result.rusage = new Unix.Rusage();

        return result;
    }

    private void startSlave(Slave slave, String desc, PairId newPairId) {
        Thread thread = new Thread(slave);
        thread.start();

        String fmt = "%s: thread=%s, pairId=%s, pid=%s";
        Pid pid = slave.getPid();
        String name = thread.getName();
        mLogger.info(fmt, desc, name, newPairId, pid);
    }

    private SyscallResult.Generic32 runPoll(PollReaction reaction,
                                            int timeout) throws IOException,
                                                                SigkillException {
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

    private void registerFile(Process.FileRegisteringCallback callback,
                              SyscallResult.Generic32 result) {
        int fd;
        try {
            fd = mProcess.registerFile(callback);
        }
        catch (UnixException e) {
            result.setError(e.getErrno());
            return;
        }

        result.retval = fd;
    }

    private SyscallResult.Generic32 renameActualFile(NormalizedPath from,
                                                     NormalizedPath to) {
        mLogger.info("rename actual file: from=%s, to=%s", from, to);
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (!mPermissions.isAllowed(from)) {
            result.setError(Errno.ENOENT);
            return result;
        }
        if (!mPermissions.isAllowed(to)) {
            result.setError(Errno.EPERM);
            return result;
        }
        if (!new File(from.toString()).renameTo(new File(to.toString()))) {
            result.setError(Errno.ENOENT);
            return result;
        }

        return result;
    }

    private SyscallResult.Generic32 openActualFile(NormalizedPath absPath, int flags, int mode) throws IOException {
        mLogger.info("open actual file: %s", absPath);
        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (!mPermissions.isAllowed(absPath)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        registerFile(new OpenCallback(absPath, flags), result);
        return result;
    }

    private SyscallResult.Stat statActualFile(NormalizedPath absPath) throws IOException {
        mLogger.info("stat actual file: %s", absPath);

        SyscallResult.Stat result = new SyscallResult.Stat();

        if (!mPermissions.isAllowed(absPath)) {
            result.retval = -1;
            result.errno = Errno.ENOENT;
            return result;
        }

        File file = new File(absPath.toString());
        if (!file.exists()) {
            result.setError(Errno.ENOENT);
            return result;
        }

        Unix.Stat stat = new Unix.Stat(UID, GID);
        stat.st_mode = Unix.Constants.S_IRUSR
                     | Unix.Constants.S_IWUSR
                     /*| Unix.Constants.S_IRGRP
                     | Unix.Constants.S_IROTH*/
                     | (file.isFile() ? Unix.Constants.S_IFREG
                                      : Unix.Constants.S_IXUSR |
                                        /*Unix.Constants.S_IXGRP |
                                        Unix.Constants.S_IXOTH |*/
                                        Unix.Constants.S_IFDIR);
        try {
            stat.st_size = file.length();
        }
        catch (SecurityException e) {
            result.retval = -1;
            result.errno = Errno.EPERM;
            return result;
        }

        result.ub = stat;

        return result;
    }

    private SyscallResult.Readlink readlinkActualFile(NormalizedPath absPath,
                                                      long count)
                                                      throws IOException {
        mLogger.info("readlink actual file: %s", absPath);

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
        mLogger.info("access actual file: %s", absPath);

        SyscallResult.Generic32 result = new SyscallResult.Generic32();

        if (!mPermissions.isAllowed(absPath)) {
            result.setError(Errno.ENOENT);
            return result;
        }
        if (!new File(absPath.toString()).exists()) {
            result.setError(Errno.ENOENT);
            return result;
        }

        return result;
    }

    private void log(String tag, String name, Unix.IoVec[] iov) {
        int len = iov.length;
        for (int i = 0; i < len; i++) {
            Unix.IoVec v = iov[i];
            String s = ByteUtil.toString(v.iov_base, (int)v.iov_len);
            mLogger.debug("%s: %s[%d]=%s", tag, name, i, s);
        }
    }

    private void logBuffer(String tag, byte[] buf, int len) {
        String s = ByteUtil.toString(buf, len);
        mLogger.debug("%s: %s", tag, s);
    }

    private void logBuffer(String tag, byte[] buf) {
        logBuffer(tag, buf, buf.length);
    }

    /*
    private void logPossibleDyingMessage(byte[] buf) {
        int size = Math.min(buf.length, 256);
        for (int i = 0; i < size; i++) {
            String fmt = "write(2) to fd 2: buf[%d]=0x%02x (%s)";
            byte c = buf[i];
            mLogger.debug(fmt, i, c, CHARS[c]);
        }
    }
    */

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
        UnixFile file;
        try {
            file = mProcess.getLockedFile(fd);
        }
        catch (UnixException e) {
            throw new GetSocketException(e.getErrno());
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
        //return mLinks.get(normPath);
        String s = String.format("/storage/emulated/0/nexec%s", normPath);
        try {
            return new NormalizedPath(s);
        }
        catch (NormalizedPath.InvalidPathException e) {
            throw new IOException(e);
        }
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

    private void initialize(Application application, Process process,
                            SyscallReadableChannel hubIn,
                            SyscallWritableChannel hubOut,
                            NormalizedPath currentDirectory,
                            Permissions permissions, Links links,
                            Listener listener) throws IOException {
        mApplication = application;
        mProcess = process;
        mIn = hubIn;
        mOut = hubOut;
        mPermissions = permissions;
        mLinks = links;
        setListener(listener);
        mCurrentDirectory = currentDirectory;

        mAlarm = mApplication.getAlarm();
        Pipe signalNotification = Pipe.open();
        mSignalNotificationSource = signalNotification.source();
        mSignalNotificationSink = signalNotification.sink();

        mHelper = new SlaveHelper(this, mIn, mOut);
        mFcntlProcs = new FcntlProcs();
        mFcntlProcs.put(Unix.Constants.F_GETFD, new FGetFdProc());
        mFcntlProcs.put(Unix.Constants.F_SETFD, new FSetFdProc());
        mFcntlProcs.put(Unix.Constants.F_GETFL, new FGetFlProc());
        mFcntlProcs.put(Unix.Constants.F_SETFL, new FSetFlProc());
        mSignalNotification = ByteBuffer.allocate(1).put((byte)42);
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
