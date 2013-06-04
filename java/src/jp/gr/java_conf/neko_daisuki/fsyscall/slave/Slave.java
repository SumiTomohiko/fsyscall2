package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;
import jp.gr.java_conf.neko_daisuki.fsyscall.CommandDispatcher;
import jp.gr.java_conf.neko_daisuki.fsyscall.Encoder;
import jp.gr.java_conf.neko_daisuki.fsyscall.Errno;
import jp.gr.java_conf.neko_daisuki.fsyscall.L;
import jp.gr.java_conf.neko_daisuki.fsyscall.PayloadSize;
import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.ProtocolError;
import jp.gr.java_conf.neko_daisuki.fsyscall.SyscallResult;
import jp.gr.java_conf.neko_daisuki.fsyscall.Unix;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallInputStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.SyscallOutputStream;

public class Slave extends Worker {

    private static class Logger {

        public static void info(String message) {
            L.info(buildMessage(message));
        }

        private static String buildMessage(String message) {
            return String.format("Slave: %s", message);
        }
    }

    private static class UnixException extends Exception {

        private Errno mErrno;

        public UnixException(Errno errno, Throwable e) {
            super(e);
            initialize(errno);
        }

        public UnixException(Errno errno) {
            initialize(errno);
        }

        public Errno getErrno() {
            return mErrno;
        }

        private void initialize(Errno errno) {
            mErrno = errno;
        }
    }

    private interface UnixFile {

        public int read(byte[] buffer) throws UnixException;
        public void close() throws UnixException;
    }

    private static class UnixInputFile implements UnixFile {

        private InputStream mIn;

        public UnixInputFile(InputStream in) {
            mIn = in;
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

        public void close() throws UnixException {
            try {
                mIn.close();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EBADF, e);
            }
        }
    }

    private static class UnixOutputFile implements UnixFile {

        private OutputStream mOut;

        public UnixOutputFile(OutputStream out) {
            mOut = out;
        }

        public int read(byte[] buffer) throws UnixException {
            throw new UnixException(Errno.EBADF);
        }

        public void close() throws UnixException {
            try {
                mOut.close();
            }
            catch (IOException e) {
                throw new UnixException(Errno.EBADF, e);
            }
        }
    }

    private static final int UNIX_FILE_NUM = 256;

    private Application mApplication;
    private SyscallInputStream mIn;
    private SyscallOutputStream mOut;

    private UnixFile[] mFiles;

    // Cache
    private SyscallResult mResult;

    private SlaveHelper mHelper;

    public Slave(Application application, InputStream in, OutputStream out) throws IOException {
        Logger.info("a slave is starting.");

        mApplication = application;
        mIn = new SyscallInputStream(in);
        mOut = new SyscallOutputStream(out);
        mHelper = new SlaveHelper(this, mIn, mOut);

        mFiles = new UnixFile[UNIX_FILE_NUM];
        mFiles[0] = new UnixInputFile(System.in);
        mFiles[1] = new UnixOutputFile(System.out);
        mFiles[2] = new UnixOutputFile(System.err);

        mResult = new SyscallResult();

        writeOpenedFileDescriptors();
        Logger.info("file descripters were transfered from the slave.");
    }

    public boolean isReady() throws IOException {
        return mIn.isReady();
    }

    public void work() throws IOException {
        Logger.info("performing the work.");

        Command command = mIn.readCommand();
        Logger.info(String.format("read command: %s", command.toString()));

        mHelper.dispatchCommand(command);

        Logger.info("finished the work.");
    }

    public SyscallResult doOpen(String path, int flags, int mode) throws IOException {
        SyscallResult result = getSyscallResult();

        int fd = findFreeSlotOfFile();
        if (fd < 0) {
            result.n = -1;
            result.errno = Errno.ENFILE;
            return result;
        }

        UnixFile file;
        try {
            switch (flags & Unix.Constants.O_ACCMODE) {
            case Unix.Constants.O_RDONLY:
                file = new UnixInputFile(new FileInputStream(path));
                break;
            case Unix.Constants.O_WRONLY:
                // XXX: Here ignores O_CREAT.
                file = new UnixOutputFile(new FileOutputStream(path));
                break;
            default:
                result.n = -1;
                result.errno = Errno.EINVAL;
                return result;
            }
        }
        catch (FileNotFoundException e) {
            result.n = -1;
            result.errno = Errno.ENOENT;
            return result;
        }
        catch (SecurityException e) {
            result.n = -1;
            result.errno = Errno.EPERM;
            return result;
        }

        mFiles[fd] = file;

        result.n = fd;
        return result;
    }

    public SyscallResult doRead(int fd, char[] buf, long nbytes) throws IOException {
        return null;
    }

    public SyscallResult doLseek(int fd, long offset, int whence) throws IOException {
        return null;
    }

    public SyscallResult doMmap(char[] addr, long len, int prot, int flags, int fd, long pos) throws IOException {
        return null;
    }

    public SyscallResult doPread(int fd, char[] iovp, long iovcnt, long offset) throws IOException {
        return null;
    }

    public SyscallResult doIssetugid() throws IOException {
        return null;
    }

    public SyscallResult doLstat(String path, Unix.Stat stat) throws IOException {
        return null;
    }

    public SyscallResult doFstat(int fd, Unix.Stat stat) throws IOException {
        return null;
    }

    public SyscallResult doStat(String path, Unix.Stat stat) throws IOException {
        return null;
    }

    public SyscallResult doWritev(int fd, char[] iovp, long iovcnt) throws IOException {
        return null;
    }

    public SyscallResult doSelect(int nfds, Unix.FdSet in, Unix.FdSet ou, Unix.FdSet ex, Unix.TimeVal tv) throws IOException {
        return null;
    }

    public SyscallResult doReadlink(String path, String buf, long count) throws IOException {
        return null;
    }

    public SyscallResult doIoctl(int fd, long com, char[] data) throws IOException {
        return null;
    }

    public SyscallResult doAccess(String path, int flags) throws IOException {
        return null;
    }

    public SyscallResult doLink(String path1, String path2) throws IOException {
        return null;
    }

    public SyscallResult doClose(int fd) throws IOException {
        SyscallResult result = getSyscallResult();

        UnixFile file = mFiles[fd];
        if (file == null) {
            result.n = -1;
            result.errno = Errno.EBADF;
            return result;
        }

        try {
            file.close();
        }
        catch (UnixException e) {
            result.n = -1;
            result.errno = e.getErrno();
            return result;
        }

        mFiles[fd] = null;

        result.n = 0;
        return result;
    }

    public SyscallResult doWrite(int fd, char[] buf, long nbytes) throws IOException {
        return null;
    }

    public SyscallResult doExit(int rval) throws IOException {
        mIn.close();
        mOut.close();
        mApplication.removeSlave(this);
        mApplication.setExitStatus(rval);
        return null;
    }

    public void writeResultGeneric(Command command, SyscallResult result) throws IOException {
        byte[] returnedValue = Encoder.encodeInteger(result.n);
        byte[] errno = result.n != -1 ? new byte[0] : Encoder.encodeInteger(result.errno.toInteger());
        int len = returnedValue.length + errno.length;
        PayloadSize payloadSize = PayloadSize.fromInteger(len);

        mOut.writeCommand(command);
        mOut.writePayloadSize(payloadSize);
        mOut.write(returnedValue);
        mOut.write(errno);
    }

    private SyscallResult getSyscallResult() {
        return mResult;
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

        mOut.writeInteger(len);
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
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=java
 */
