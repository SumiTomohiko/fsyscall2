package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.HashMap;
import java.util.Map;

public class Signal {

    public static final Signal SIGHUP = new Signal(1, "SIGHUP");
    public static final Signal SIGINT = new Signal(2, "SIGINT");
    public static final Signal SIGQUIT = new Signal(3, "SIGQUIT");
    public static final Signal SIGILL = new Signal(4, "SIGILL");
    public static final Signal SIGTRAP = new Signal(5, "SIGTRAP");
    public static final Signal SIGABRT = new Signal(6, "SIGABRT");
    public static final Signal SIGIOT = SIGABRT;
    public static final Signal SIGEMT = new Signal(7, "SIGEMT");
    public static final Signal SIGFPE = new Signal(8, "SIGFPE");
    public static final Signal SIGKILL = new Signal(9, "SIGKILL");
    public static final Signal SIGBUS = new Signal(10, "SIGBUS");
    public static final Signal SIGSEGV = new Signal(11, "SIGSEGV");
    public static final Signal SIGSYS = new Signal(12, "SIGSYS");
    public static final Signal SIGPIPE = new Signal(13, "SIGPIPE");
    public static final Signal SIGALRM = new Signal(14, "SIGALRM");
    public static final Signal SIGTERM = new Signal(15, "SIGTERM");
    public static final Signal SIGURG = new Signal(16, "SIGURG");
    public static final Signal SIGSTOP = new Signal(17, "SIGSTOP");
    public static final Signal SIGTSTP = new Signal(18, "SIGTSTP");
    public static final Signal SIGCONT = new Signal(19, "SIGCONT");
    public static final Signal SIGCHLD = new Signal(20, "SIGCHLD");
    public static final Signal SIGTTIN = new Signal(21, "SIGTTIN");
    public static final Signal SIGTTOU = new Signal(22, "SIGTTOU");
    public static final Signal SIGIO = new Signal(23, "SIGIO");
    public static final Signal SIGXCPU = new Signal(24, "SIGXCPU");
    public static final Signal SIGXFSZ = new Signal(25, "SIGXFSZ");
    public static final Signal SIGVTALRM = new Signal(26, "SIGVTALRM");
    public static final Signal SIGPROF = new Signal(27, "SIGPROF");
    public static final Signal SIGWINCH = new Signal(28, "SIGWINCH");
    public static final Signal SIGINFO = new Signal(29, "SIGINFO");
    public static final Signal SIGUSR1 = new Signal(30, "SIGUSR1");
    public static final Signal SIGUSR2 = new Signal(31, "SIGUSR2");
    public static final Signal SIGTHR = new Signal(32, "SIGTHR");
    public static final Signal SIGLWP = SIGTHR;

    private static final Map<Integer, Signal> mSignals = new HashMap<Integer, Signal>();

    private int mNumber;
    private String mName;

    private Signal(int number, String name) {
        mNumber = number;
        mName = name;
    }

    public static Signal valueOf(int signum) {
        return mSignals.get(signum);
    }

    public String getName() {
        return mName;
    }

    public int getNumber() {
        return mNumber;
    }

    @Override
    public int hashCode() {
        return mName.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        Signal signal;
        try {
            signal = (Signal)o;
        }
        catch (ClassCastException _) {
            return false;
        }
        return mNumber == signal.mNumber;
    }

    static {
        Signal[] signals = { SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
                             SIGIOT, SIGEMT, SIGFPE, SIGKILL, SIGBUS, SIGSEGV,
                             SIGSYS, SIGPIPE, SIGALRM, SIGTERM, SIGURG, SIGSTOP,
                             SIGTSTP, SIGCONT, SIGCHLD, SIGTTIN, SIGTTOU, SIGIO,
                             SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH,
                             SIGINFO, SIGUSR1, SIGUSR2, SIGTHR };
        for (int i = 0; i < signals.length; i++) {
            Signal sig = signals[i];
            mSignals.put(sig.getNumber(), sig);
        }
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
