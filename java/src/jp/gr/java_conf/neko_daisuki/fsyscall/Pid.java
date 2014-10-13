package jp.gr.java_conf.neko_daisuki.fsyscall;

/**
 * Process Id. This is different from PairId.
 */
public class Pid {

    private int mPid;

    public Pid(int pid) {
        mPid = pid;
    }

    public Pid(Pid pid) {
        mPid = pid.toInteger();
    }

    public int toInteger() {
        return mPid;
    }

    public int hashCode() {
        return new Integer(mPid).hashCode();
    }

    public boolean equals(Object obj) {
        Pid pid = (Pid)obj;
        return toInteger() == pid.toInteger();
    }

    public String toString() {
        return Integer.toString(toInteger());
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
