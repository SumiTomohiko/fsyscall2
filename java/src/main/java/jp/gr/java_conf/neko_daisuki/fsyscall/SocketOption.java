package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.HashMap;
import java.util.Map;

public class SocketOption {

    public static final SocketOption SO_DEBUG = new SocketOption(
            "SO_DEBUG",
            0x0001);
    public static final SocketOption SO_ACCEPTCONN = new SocketOption(
            "SO_ACCEPTCONN",
            0x0002);
    public static final SocketOption SO_REUSEADDR = new SocketOption(
            "SO_REUSEADDR",
            0x0004);
    public static final SocketOption SO_KEEPALIVE = new SocketOption(
            "SO_KEEPALIVE",
            0x0008);
    public static final SocketOption SO_DONTROUTE = new SocketOption(
            "SO_DONTROUTE",
            0x0010);
    public static final SocketOption SO_BROADCAST = new SocketOption(
            "SO_BROADCAST",
            0x0020);
    public static final SocketOption SO_USELOOPBACK = new SocketOption(
            "SO_USELOOPBACK",
            0x0040);
    public static final SocketOption SO_LINGER = new SocketOption(
            "SO_LINGER",
            0x0080);
    public static final SocketOption SO_OOBINLINE = new SocketOption(
            "SO_OOBINLINE",
            0x0100);
    public static final SocketOption SO_REUSEPORT = new SocketOption(
            "SO_REUSEPORT",
            0x0200);
    public static final SocketOption SO_TIMESTAMP = new SocketOption(
            "SO_TIMESTAMP",
            0x0400);
    public static final SocketOption SO_NOSIGPIPE = new SocketOption(
            "SO_NOSIGPIPE",
            0x0800);
    public static final SocketOption SO_ACCEPTFILTER = new SocketOption(
            "SO_ACCEPTFILTER",
            0x1000);
    public static final SocketOption SO_BINTIME = new SocketOption(
            "SO_BINTIME",
            0x2000);
    public static final SocketOption SO_NO_OFFLOAD = new SocketOption(
            "SO_NO_OFFLOAD",
            0x4000);
    public static final SocketOption SO_NO_DDP = new SocketOption(
            "SO_NO_DDP",
            0x8000);

    public static final SocketOption SO_SNDBUF = new SocketOption(
            "SO_SNDBUF",
            0x1001);
    public static final SocketOption SO_RCVBUF = new SocketOption(
            "SO_RCVBUF",
            0x1002);
    public static final SocketOption SO_SNDLOWAT = new SocketOption(
            "SO_SNDLOWAT",
            0x1003);
    public static final SocketOption SO_RCVLOWAT = new SocketOption(
            "SO_RCVLOWAT",
            0x1004);
    public static final SocketOption SO_SNDTIMEO = new SocketOption(
            "SO_SNDTIMEO",
            0x1005);
    public static final SocketOption SO_RCVTIMEO = new SocketOption(
            "SO_RCVTIMEO",
            0x1006);
    public static final SocketOption SO_ERROR = new SocketOption(
            "SO_ERROR",
            0x1007);
    public static final SocketOption SO_TYPE = new SocketOption(
            "SO_TYPE",
            0x1008);
    public static final SocketOption SO_LABEL = new SocketOption(
            "SO_LABEL",
            0x1009);
    public static final SocketOption SO_PEERLABEL = new SocketOption(
            "SO_PEERLABEL",
            0x1010);
    public static final SocketOption SO_LISTENQLIMIT = new SocketOption(
            "SO_LISTENQLIMIT",
            0x1011);
    public static final SocketOption SO_LISTENQLEN = new SocketOption(
            "SO_LISTENQLEN",
            0x1012);
    public static final SocketOption SO_LISTENINCQLEN = new SocketOption(
            "SO_LISTENINCQLEN",
            0x1013);
    public static final SocketOption SO_SETFIB = new SocketOption(
            "SO_SETFIB",
            0x1014);
    public static final SocketOption SO_USER_COOKIE = new SocketOption(
            "SO_USER_COOKIE",
            0x1015);
    public static final SocketOption SO_PROTOCOL = new SocketOption(
            "SO_PROTOCOL",
            0x1016);
    public static final SocketOption SO_PROTOTYPE = SO_PROTOCOL;

    private static final Map<Integer, SocketOption> mOptions;

    private String mName;
    private int mValue;

    private SocketOption(String name, int value) {
        mName = name;
        mValue = value;
    }

    @Override
    public int hashCode() {
        return Integer.valueOf(mValue).hashCode();
    }

    @Override
    public boolean equals(Object o) {
        SocketOption opt;
        try {
            opt = (SocketOption)o;
        }
        catch (ClassCastException unused) {
            return false;
        }

        return mValue == opt.mValue;
    }

    public String toString() {
        return mName;
    }

    public int intValue() {
        return mValue;
    }

    public static SocketOption valueOf(int optname) {
        return mOptions.get(Integer.valueOf(optname));
    }

    public static String toString(int optname) {
        SocketOption option = valueOf(optname);
        return option != null ? option.toString() : "unknown socket option";
    }

    static {
        mOptions = new HashMap<Integer, SocketOption>();

        SocketOption[] options = {
            SO_DEBUG, SO_ACCEPTCONN, SO_REUSEADDR, SO_KEEPALIVE, SO_DONTROUTE,
            SO_BROADCAST, SO_USELOOPBACK, SO_LINGER, SO_OOBINLINE, SO_REUSEPORT,
            SO_TIMESTAMP, SO_NOSIGPIPE, SO_ACCEPTFILTER, SO_BINTIME,
            SO_NO_OFFLOAD, SO_NO_DDP, SO_SNDBUF, SO_RCVBUF, SO_SNDLOWAT,
            SO_RCVLOWAT, SO_SNDTIMEO, SO_RCVTIMEO, SO_ERROR, SO_TYPE, SO_LABEL,
            SO_PEERLABEL, SO_LISTENQLIMIT, SO_LISTENQLEN, SO_LISTENINCQLEN,
            SO_SETFIB, SO_USER_COOKIE, SO_PROTOCOL
        };
        int len = options.length;
        for (int i = 0; i < len; i++) {
            SocketOption option = options[i];
            mOptions.put(Integer.valueOf(option.mValue), option);
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
