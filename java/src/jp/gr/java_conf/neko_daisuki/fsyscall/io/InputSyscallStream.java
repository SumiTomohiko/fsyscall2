package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.InputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.Command;

public class InputSyscallStream {

    private InputStream mIn;

    public InputSyscallStream(InputStream in) {
        mIn = in;
    }

    public boolean isReady() throws IOException {
        return 0 < mIn.available();
    }

    public Command readCommand() throws IOException {
        return Command.fromInteger(readInteger());
    }

    /**
     * Reads signed int (32bits). This method cannot handle unsigned int.
     */
    public int readInteger() throws IOException {
        int n = 0;
        int shift = 0;
        int m;
        while (((m = mIn.read()) & 0x80) != 0) {
            n += ((m & 0x7f) << shift);
            shift += 7;
        }
        return n;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
