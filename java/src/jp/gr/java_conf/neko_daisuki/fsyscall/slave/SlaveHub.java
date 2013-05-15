package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.io.InputSyscallStream;
import jp.gr.java_conf.neko_daisuki.fsyscall.io.OutputSyscallStream;

public class SlaveHub extends Worker {

    private InputSyscallStream mMhubIn;
    private OutputSyscallStream mMhubOut;
    private InputSyscallStream mSlaveIn;
    private OutputSyscallStream mSlaveOut;

    public SlaveHub(InputStream mhubIn, OutputStream mhubOut, InputStream slaveIn, OutputStream slaveOut) {
        mMhubIn = new InputSyscallStream(mhubIn);
        mMhubOut = new OutputSyscallStream(mhubOut);
        mSlaveIn = new InputSyscallStream(slaveIn);
        mSlaveOut = new OutputSyscallStream(slaveOut);
    }

    public boolean isReady() throws IOException {
        return mMhubIn.isReady() || mSlaveIn.isReady();
    }

    public void work() {
        // TODO
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
