package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import jp.gr.java_conf.neko_daisuki.fsyscall.DirEntries;
import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;

abstract class UnixFile implements EventScannee {

    private boolean mNonBlocking = false;
    private boolean mCloseOnExec = false;
    private ReentrantReadWriteLock.WriteLock mLock;
    private int mRefCount = 1;

    private Alarm mAlarm;

    public UnixFile(Alarm alarm) {
        mLock = new ReentrantReadWriteLock().writeLock();
        mAlarm = alarm;
    }

    public void lock() {
        mLock.lock();
    }

    public void unlock() {
        mLock.unlock();
    }

    public void setCloseOnExec(boolean closeOnExec) {
        mCloseOnExec = closeOnExec;
    }

    public boolean getCloseOnExec() {
        return mCloseOnExec;
    }

    public void incRefCount() {
        checkLock();
        mRefCount++;
    }

    public void close() throws UnixException {
        checkLock();

        mRefCount--;
        if (mRefCount == 0) {
            doClose();
        }
    }

    /**
     * Returns true when the peer has disconnected.
     */
    public boolean isDisconnected() {
        return false;
    }

    public void enableNonBlocking(boolean nonBlocking) {
        mNonBlocking = nonBlocking;
    }

    public int write(byte[] buffer) throws UnixException {
        int nBytes = doWrite(buffer);
        mAlarm.alarm();
        return nBytes;
    }

    public DirEntries getdirentries(int nMax) throws UnixException {
        throw new UnixException(Errno.EBADF);
    }

    public abstract boolean isReadyToRead() throws IOException;
    public abstract boolean isReadyToWrite() throws IOException;
    public abstract int read(byte[] buffer) throws UnixException;
    public abstract long pread(byte[] buffer, long offset) throws UnixException;
    public abstract long lseek(long offset, int whence) throws UnixException;
    public abstract Unix.Stat fstat() throws UnixException;
    public abstract long getFilterFlags();
    public abstract void clearFilterFlags();

    protected boolean isNonBlocking() {
        return mNonBlocking;
    }

    protected Alarm getAlarm() {
        return mAlarm;
    }

    protected abstract int doWrite(byte[] buffer) throws UnixException;
    protected abstract void doClose() throws UnixException;

    private void checkLock() {
        if (!mLock.isHeldByCurrentThread()) {
            throw new IllegalStateException();
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
