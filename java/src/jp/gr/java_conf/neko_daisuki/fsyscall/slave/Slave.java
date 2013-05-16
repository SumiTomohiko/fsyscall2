package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.io.InputSyscallStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.OutputSyscallStream;

public class Slave extends Worker {

    private static class UnixFile {

        public InputStream in;
        public OutputStream out;
    }

    private static final int UNIX_FILE_NUM = 256;

    private InputSyscallStream mIn;
    private OutputSyscallStream mOut;

    private int mPid;
    private UnixFile[] mFiles;

    public Slave(int pid, InputStream in, OutputStream out) {
        mIn = new InputSyscallStream(in);
        mOut = new OutputSyscallStream(out);

        mPid = pid;
        mFiles = new UnixFile[UNIX_FILE_NUM];
    }

    public boolean isReady() throws IOException {
        return mIn.isReady();
    }

    public void work() {
        // TODO
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
