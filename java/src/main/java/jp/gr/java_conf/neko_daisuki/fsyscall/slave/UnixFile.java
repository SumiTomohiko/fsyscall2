package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;

abstract class UnixFile {

    private abstract class Closer {

        public abstract void close() throws UnixException;
    }

    private class TrueCloser extends Closer {

        public void close() throws UnixException {
            doClose();
        }
    }

    private class RefCountCloser extends Closer {

        public void close() throws UnixException {
            mRefCount--;
            mCloser = mRefCount == 1 ? new TrueCloser() : mCloser;
        }
    }

    private int mRefCount;
    private Closer mCloser;
    private boolean mNonBlocking = false;
    private boolean mCloseOnExec = false;
    private Lock mLock = new ReentrantReadWriteLock().writeLock();

    public UnixFile() {
        mRefCount = 1;
        mCloser = new TrueCloser();
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

    public void acquire() {
        mRefCount++;
        mCloser = mRefCount == 2 ? new RefCountCloser() : mCloser;
    }

    public void close() throws UnixException {
        mCloser.close();
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

    protected boolean isNonBlocking() {
        return mNonBlocking;
    }

    protected abstract void doClose() throws UnixException;
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
