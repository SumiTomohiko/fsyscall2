package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.Collection;
import java.util.HashSet;

public class SocketOptions {

    private Collection<SocketOption> mOptions = new HashSet<SocketOption>();

    public void add(SocketOption option) {
        mOptions.add(option);
    }

    public void remove(SocketOption option) {
        mOptions.remove(option);
    }

    public boolean contains(SocketOption option) {
        return mOptions.contains(option);
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
