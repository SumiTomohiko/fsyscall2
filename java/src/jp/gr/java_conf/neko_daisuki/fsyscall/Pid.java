package jp.gr.java_conf.neko_daisuki.fsyscall;

public class Pid {

    private int mPid;

    public Pid(int pid) {
        mPid = pid;
    }

    public Pid(Pid pid) {
        mPid = pid.getInteger();
    }

    public int getInteger() {
        return mPid;
    }

    public int hashCode() {
        return new Integer(mPid).hashCode();
    }

    public boolean equals(Object obj) {
        Pid pid = (Pid)obj;
        return getInteger() == pid.getInteger();
    }

    public String toString() {
        return Integer.toString(getInteger());
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
