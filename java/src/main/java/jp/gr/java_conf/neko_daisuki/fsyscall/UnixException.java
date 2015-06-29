package jp.gr.java_conf.neko_daisuki.fsyscall;

public class UnixException extends Exception {

    private Errno mErrno;

    public UnixException(Errno errno, String message) {
        super(message);
        initialize(errno);
    }

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

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
