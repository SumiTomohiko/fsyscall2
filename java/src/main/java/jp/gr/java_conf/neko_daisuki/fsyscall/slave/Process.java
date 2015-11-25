package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.Collection;
import java.util.HashSet;

import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;
import jp.gr.java_conf.neko_daisuki.fsyscall.Signal;
import jp.gr.java_conf.neko_daisuki.fsyscall.UnixException;

class Process {

    private Pid mPid;
    private Collection<Slave> mSlaves = new HashSet<Slave>();
    private Integer mExitStatus;

    public Process(Pid pid) {
        mPid = pid;
    }

    public Integer getExitStatus() {
        return mExitStatus;
    }

    public void setExitStatus(int val) {
        mExitStatus = Integer.valueOf(val);
    }

    public Pid getPid() {
        return mPid;
    }

    public void remove(Slave slave) {
        synchronized (mSlaves) {
            mSlaves.remove(slave);
        }
    }

    public void add(Slave slave) {
        synchronized (mSlaves) {
            mSlaves.add(slave);
        }
    }

    public int size() {
        synchronized (mSlaves) {
            return mSlaves.size();
        }
    }

    public void terminate() {
        synchronized (mSlaves) {
            for (Slave slave: mSlaves) {
                slave.terminate();
            }
        }
    }

    public void kill(Signal sig) throws UnixException {
        synchronized (mSlaves) {
            for (Slave slave: mSlaves) {
                slave.kill(sig);
                break;
            }
        }
    }

    public boolean isZombie() {
        return size() == 0;
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
