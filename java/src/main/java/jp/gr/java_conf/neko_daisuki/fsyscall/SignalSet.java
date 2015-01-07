package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

public class SignalSet implements Cloneable {

    private Collection<Signal> mSet;

    public SignalSet() {
        mSet = new HashSet<Signal>();
    }

    public SignalSet(Collection<Signal> c) {
        mSet = new HashSet<Signal>(c);
    }

    public SignalSet clone() {
        SignalSet c = new SignalSet();
        for (Signal signal: mSet) {
            c.add(signal);
        }
        return c;
    }

    public void add(Signal signal) {
        synchronized (mSet) {
            mSet.add(signal);
        }
    }

    public void remove(Signal signal) {
        synchronized (mSet) {
            mSet.remove(signal);
        }
    }

    public boolean contains(Signal signal) {
        synchronized (mSet) {
            return mSet.contains(signal);
        }
    }

    public Collection<Signal> toCollection() {
        Collection<Signal> c;
        synchronized (mSet) {
            if (mSet.isEmpty()) {
                return Collections.emptySet();
            }
            c = new HashSet<Signal>(mSet);
            mSet.clear();
        }
        return c;
    }

    public String toString() {
        return String.format("SignalSet(%s)", listSignals());
    }

    private String listSignals() {
        List<String> l;
        synchronized (mSet) {
            if (mSet.isEmpty()) {
                return "";
            }
            l = new ArrayList<String>();
            for (Signal sig: mSet) {
                l.add(sig.getName());
            }
        }
        StringBuilder buffer = new StringBuilder(l.get(0));
        int size = l.size();
        for (int i = 1; i < size; i++) {
            buffer.append(", ");
            buffer.append(l.get(i));
        }
        return buffer.toString();
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
