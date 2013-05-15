package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.io.InputSyscallStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.OutputSyscallStream;

public class Slave extends Worker {

    private InputSyscallStream mIn;
    private OutputSyscallStream mOut;

    public Slave(InputStream in, OutputStream out) {
        mIn = new InputSyscallStream(in);
        mOut = new OutputSyscallStream(out);
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
