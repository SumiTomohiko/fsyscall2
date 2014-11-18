package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

public class SignalSet implements Iterable<Signal> {

    private Collection<Signal> mSet;

    public SignalSet() {
        mSet = new HashSet<Signal>();
    }

    public SignalSet(Collection<Signal> c) {
        mSet = new HashSet<Signal>(c);
    }

    public void add(Signal signal) {
        mSet.add(signal);
    }

    public void clear() {
        mSet.clear();
    }

    @Override
    public Iterator<Signal> iterator() {
        return mSet.iterator();
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
