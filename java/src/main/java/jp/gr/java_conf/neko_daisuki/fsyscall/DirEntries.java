package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.Iterator;
import java.util.List;

public class DirEntries implements Iterable<Unix.DirEnt> {

    private List<Unix.DirEnt> mEntries;
    private int mBase;

    public DirEntries(List<Unix.DirEnt> entries, int base) {
        mEntries = entries;
        mBase = base;
    }

    public DirEntries(List<Unix.DirEnt> entries) {
        this(entries, 0);
    }

    public Iterator<Unix.DirEnt> iterator() {
        return mEntries.iterator();
    }

    public int size() {
        return mEntries.size();
    }

    public int getBase() {
        return mBase;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder("[");
        String sep = "";
        for (Unix.DirEnt entry: mEntries) {
            buf.append(sep);
            buf.append(entry.toString());
            sep = ", ";
        }
        buf.append("]");

        return String.format("DirEntries(entries=%s, base=%d)", buf, mBase);
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
