package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.InputStream;
import java.io.OutputStream;

public interface SocketCore {

    public InputStream getInputStream();
    public OutputStream getOutputStream();
    public void close();
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
