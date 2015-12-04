package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.Collection;
import java.util.HashSet;

import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.PollFds;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;

class Process {

    public interface FileRegisteringCallback {

        public UnixFile call() throws UnixException;
    }

    public class SelectFiles {

        public UnixFile[] inFiles;
        public UnixFile[] ouFiles;
        public UnixFile[] exFiles;
    }

    private static final int UNIX_FILE_NUM = 256;

    private static Logging.Logger mLogger;

    private Pid mPid;
    private UnixFile[] mFiles;
    private Integer mExitStatus;

    private Collection<Slave> mSlaves = new HashSet<Slave>();

    public Process(Pid pid) {
        initialize(pid, new UnixFile[UNIX_FILE_NUM]);
    }

    public Process(Pid pid, Process parent) {
        UnixFile[] files = parent.mFiles;
        int len = files.length;
        UnixFile[] a = new UnixFile[len];
        System.arraycopy(files, 0, a, 0, len);

        initialize(pid, a);
    }

    public SelectFiles getFiles(Unix.Fdset in, Unix.Fdset ou,
                                Unix.Fdset ex) throws UnixException {
        SelectFiles files = new SelectFiles();
        synchronized (mFiles) {
            files.inFiles = getFiles(in);
            files.ouFiles = getFiles(ou);
            files.exFiles = getFiles(ex);
        }
        return files;
    }

    public UnixFile[] getFiles(PollFds fds) throws UnixException {
        int nfds = fds.size();
        int[] da = new int[nfds];
        for (int i = 0; i < nfds; i++) {
            da[i] = fds.get(i).getFd();
        }
        return getFiles(da);
    }

    public UnixFile[] getLockedFiles(int[] fds) throws UnixException {
        UnixFile[] files = getFiles(fds);
        int nFiles = files.length;
        for (int i = 0; i < nFiles; i++) {
            files[i].lock();
        }
        return files;
    }

    public Integer getExitStatus() {
        return mExitStatus;
    }

    public void setExitStatus(int val) {
        mExitStatus = Integer.valueOf(val);
    }

    public Pid getPid() {
        return mPid;
    }

    public void remove(Slave slave) {
        synchronized (mSlaves) {
            mSlaves.remove(slave);
        }
    }

    public void add(Slave slave) {
        synchronized (mSlaves) {
            mSlaves.add(slave);
        }
    }

    public int size() {
        synchronized (mSlaves) {
            return mSlaves.size();
        }
    }

    public void terminate() {
        synchronized (mSlaves) {
            for (Slave slave: mSlaves) {
                slave.terminate();
            }
        }
    }

    public void kill(Signal sig) throws UnixException {
        synchronized (mSlaves) {
            for (Slave slave: mSlaves) {
                slave.kill(sig);
                break;
            }
        }
    }

    public boolean isZombie() {
        return size() == 0;
    }

    public void closeFile(int fd) throws UnixException {
        synchronized (mFiles) {
            UnixFile file = getLockedFile(fd);
            try {
                file.close();
            }
            finally {
                file.unlock();
            }
            mFiles[fd] = null;
        }
    }

    /**
     * Returns a file of <var>fd</var> or null. A returned file is locked. You
     * M_U_S_T unlock this.
     */
    public UnixFile getLockedFile(int fd) throws UnixException {
        UnixFile file;
        synchronized (mFiles) {
            try {
                file = mFiles[fd];
            }
            catch (IndexOutOfBoundsException e) {
                throw new UnixException(Errno.EBADF, e);
            }
        }
        file.lock();
        return file;
    }

    public int[] registerFiles(UnixFile[] files) throws UnixException {
        int nFiles = files.length;
        int[] fds = new int[nFiles];
        synchronized (mFiles) {
            for (int i = 0; i < nFiles; i++) {
                fds[i] = registerFile(files[i]);
            }
        }
        return fds;
    }

    public void registerFileAt(UnixFile file, int at) {
        mFiles[at] = file;
        mLogger.info("new file registered: file=%s, fd=%d", file, at);
    }

    public int registerFile(FileRegisteringCallback callback) throws UnixException {
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

    private void initialize(Pid pid, UnixFile[] files) {
        mPid = pid;
        mFiles = files;
    }

    private UnixFile[] getFiles(Unix.Fdset fds) throws UnixException {
        int nfds = fds.size();
        int[] da = new int[nfds];
        for (int i = 0; i < nfds; i++) {
            da[i] = fds.get(i);
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

    private int findFreeSlotOfFile() {
        int len = mFiles.length;
        int i;
        for (i = 0; (i < len) && (mFiles[i] != null); i++) {
        }
        return i < len ? i : -1;
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

    static {
        mLogger = new Logging.Logger("Process");
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
