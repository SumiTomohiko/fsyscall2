package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.Pid;

class Processes implements Iterable<Process> {

    private Map<Pid, Process> mMap = new HashMap<Pid, Process>();

    public boolean isEmpty() {
        synchronized (mMap) {
            return mMap.isEmpty();
        }
    }

    public void add(Process process) {
        synchronized (mMap) {
            mMap.put(process.getPid(), process);
        }
    }

    public Process get(Pid pid) {
        synchronized (mMap) {
            return mMap.get(pid);
        }
    }

    public Process remove(Pid pid) {
        synchronized (mMap) {
            return mMap.remove(pid);
        }
    }

    public Process remove(Process process) {
        return remove(process.getPid());
    }

    public boolean contains(Pid pid) {
        synchronized (mMap) {
            return mMap.containsKey(pid);
        }
    }

    public Collection<Pid> pids() {
        synchronized (mMap) {
            return mMap.keySet();
        }
    }

    @Override
    public Iterator<Process> iterator() {
        synchronized (mMap) {
            return mMap.values().iterator();
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
