package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;

public abstract class Worker {

    public abstract boolean isReady() throws IOException;
    public abstract void work();
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
