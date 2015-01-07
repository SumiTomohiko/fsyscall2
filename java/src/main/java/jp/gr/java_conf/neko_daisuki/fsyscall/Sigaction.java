package jp.gr.java_conf.neko_daisuki.fsyscall;

public class Sigaction {

    public static enum Handler { DEFAULT, IGNORE, ACTIVE };

    public Handler sa_handler;
    public int sa_flags;
    public SignalSet sa_mask;

    public String toString() {
        String fmt = "Sigaction(sa_handler=%s, sa_flags=%d, sa_mask=%s)";
        return String.format(fmt, sa_handler, sa_flags, sa_mask);
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
