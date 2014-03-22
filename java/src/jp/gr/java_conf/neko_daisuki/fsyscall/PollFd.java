package jp.gr.java_conf.neko_daisuki.fsyscall;

public class PollFd {

    private int mFd;
    private int mEvents;
    private int mRevents;

    public PollFd(int fd, int events) {
        mFd = fd;
        mEvents = events;
    }

    public void addRevents(int events) {
        mRevents |= events;
    }

    public int getFd() {
        return mFd;
    }

    public int getEvents() {
        return mEvents;
    }

    public int getRevents() {
        return mRevents;
    }

    public String toString() {
        String fmt = "PollFd(fd=%d, events=%d, revents=%d)";
        return String.format(fmt, mFd, mEvents, mRevents);
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
