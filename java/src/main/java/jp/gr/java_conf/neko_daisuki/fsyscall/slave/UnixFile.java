package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;

abstract class UnixFile implements EventScannee {

    private boolean mNonBlocking = false;
    private boolean mCloseOnExec = false;
    private Lock mLock = new ReentrantReadWriteLock().writeLock();

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

    public void close() throws UnixException {
        doClose();
    }

    public void enableNonBlocking(boolean nonBlocking) {
        mNonBlocking = nonBlocking;
    }

    public abstract boolean isReadyToRead() throws UnixException;
    public abstract boolean isReadyToWrite() throws UnixException;
    public abstract int read(byte[] buffer) throws UnixException;
    public abstract long pread(byte[] buffer, long offset) throws UnixException;
    public abstract int write(byte[] buffer) throws UnixException;
    public abstract long lseek(long offset, int whence) throws UnixException;
    public abstract Unix.Stat fstat() throws UnixException;
    public abstract long getFilterFlags();
    public abstract void clearFilterFlags();

    protected boolean isNonBlocking() {
        return mNonBlocking;
    }

    protected abstract void doClose() throws UnixException;
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
