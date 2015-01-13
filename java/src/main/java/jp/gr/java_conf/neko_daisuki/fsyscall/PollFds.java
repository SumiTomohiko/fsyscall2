package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class PollFds implements Iterable<PollFd> {

    private List<PollFd> mFds = new LinkedList<PollFd>();

    public String toString() {
        String fmt = "PollFds(size=%d, %s)";
        return String.format(fmt, mFds.size(), buildArray());
    }

    public void add(PollFd fd) {
        mFds.add(fd);
    }

    public PollFd get(int index) {
        return mFds.get(index);
    }

    public int size() {
        return mFds.size();
    }

    public Iterator<PollFd> iterator() {
        return mFds.iterator();
    }

    private String buildArray() {
        StringBuilder buffer = new StringBuilder("[");
        int size = mFds.size();
        for (int i = 0; i < size; i++) {
            buffer.append(0 < i ? ", " : "");
            buffer.append(mFds.get(i).toString());
        }
        buffer.append("]");
        return buffer.toString();
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
