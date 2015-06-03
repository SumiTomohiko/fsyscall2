package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class KEvent {

    private static class FlagDefinitions {

        private Map<Long, String> mDefinitions;

        public FlagDefinitions() {
            mDefinitions = new HashMap<Long, String>();
        }

        public void define(long val, String name) {
            mDefinitions.put(Long.valueOf(val), name);
        }

        public String toString(long flags) {
            List<String> sa = new LinkedList<String>();
            for (long pos = 0; pos < 64; pos++) {
                long val = 1L << pos;
                if ((flags & val) == 0) {
                    continue;
                }
                String name = mDefinitions.get(Long.valueOf(val));
                if (name == null) {
                    continue;
                }
                sa.add(name);
            }
            int size = sa.size();
            StringBuilder buffer = new StringBuilder();
            for (int i = 0; i < size; i++) {
                buffer.append(i == 0 ? "" : "|");
                buffer.append(sa.get(i));
            }

            return buffer.toString();
        }
    }

    // filters
    public static final short EVFILT_READ = -1;
    public static final short EVFILT_WRITE = -2;
    public static final short EVFILT_AIO = -3;
    public static final short EVFILT_VNODE = -4;
    public static final short EVFILT_PROC = -5;
    public static final short EVFILT_SIGNAL = -6;
    public static final short EVFILT_TIMER = -7;
    public static final short EVFILT_NETDEV = -8;
    public static final short EVFILT_FS = -9;
    public static final short EVFILT_LIO = -10;
    public static final short EVFILT_USER = -11;

    // flags
    public static final int EV_ADD = 0x0001;
    public static final int EV_DELETE = 0x0002;
    public static final int EV_ENABLE = 0x0004;
    public static final int EV_DISABLE = 0x0008;
    public static final int EV_ONESHOT = 0x0010;
    public static final int EV_CLEAR = 0x0020;
    public static final int EV_RECEIPT = 0x0040;
    public static final int EV_DISPATCH = 0x0080;
    public static final int EV_SYSFLAGS = 0xF000;
    public static final int EV_FLAG1 = 0x2000;
    public static final int EV_EOF = 0x8000;
    public static final int EV_ERROR = 0x4000;

    // fflags for user
    public static final long NOTE_FFNOP = 0x00000000L;
    public static final long NOTE_FFAND = 0x40000000L;
    public static final long NOTE_FFOR = 0x80000000L;
    public static final long NOTE_FFCOPY = 0xc0000000L;
    public static final long NOTE_FFCTRLMASK = 0xc0000000L;
    public static final long NOTE_FFLAGSMASK = 0x00ffffffL;
    public static final long NOTE_TRIGGER = 0x01000000L;

    // fflags for rw
    public static final long NOTE_LOWAT = 0x0001L;

    // fflags for vnode
    public static final long NOTE_DELETE = 0x0001L;
    public static final long NOTE_WRITE = 0x0002L;
    public static final long NOTE_EXTEND = 0x0004L;
    public static final long NOTE_ATTRIB = 0x0008L;
    public static final long NOTE_LINK = 0x0010L;
    public static final long NOTE_RENAME = 0x0020L;
    public static final long NOTE_REVOKE = 0x0040L;

    // fflags for proc
    public static final long NOTE_EXIT = 0x80000000L;
    public static final long NOTE_FORK = 0x40000000L;
    public static final long NOTE_EXEC = 0x20000000L;
    public static final long NOTE_PCTRLMASK = 0xf0000000L;
    public static final long NOTE_PDATAMASK = 0x000fffffL;
    public static final long NOTE_TRACK = 0x00000001L;
    public static final long NOTE_TRACKERR = 0x00000002L;
    public static final long NOTE_CHILD = 0x00000004L;

    private static final Map<Short, String> mFilterNames;
    private static final FlagDefinitions mFlags;
    private static final Map<Integer, FlagDefinitions> mFflags;

    public long ident;
    public short filter;
    public int flags;
    public long fflags;
    public long data;
    public Object udata;

    public KEvent() {
    }

    public KEvent(long ident, short filter, int flags, long fflags, long data,
                  Object udata) {
        this.ident = ident;
        this.filter = filter;
        this.flags = flags;
        this.fflags = fflags;
        this.data = data;
        this.udata = udata;
    }

    public KEvent(KEvent kev) {
        this(kev.ident, kev.filter, kev.flags, kev.fflags, kev.data, kev.udata);
    }

    @Override
    public boolean equals(Object o) {
        KEvent kev;
        try {
            kev = (KEvent)o;
        }
        catch (ClassCastException unused) {
            return false;
        }
        return (ident == kev.ident) && (filter == kev.filter);
    }

    @Override
    public int hashCode() {
        int n = Long.valueOf(ident).hashCode();
        int m = Short.valueOf(filter).hashCode();
        return n + m;
    }

    public String toString() {
        String fmt = "KEvent(ident=%d, filter=%d (%s), flags=0x%x (%s), fflags=0x%x (%s), data=%d, udata=%s)";
        String filterName = getFilterName(filter);
        String flagsRepr = representFlags(flags);
        String fflagsRepr = representFflags(filter, fflags);
        return String.format(fmt, ident, filter, filterName, flags, flagsRepr,
                             fflags, fflagsRepr, data, udata);
    }

    private String getFilterName(short filter) {
        return mFilterNames.get(Short.valueOf(filter));
    }

    private String representFlags(int flags) {
        return mFlags.toString(flags);
    }

    private String representFflags(short filter, long fflags) {
        return mFflags.get(Integer.valueOf(filter)).toString(fflags);
    }

    static {
        mFilterNames = new HashMap<Short, String>();
        mFilterNames.put(Short.valueOf(EVFILT_READ), "EVFILT_READ");
        mFilterNames.put(Short.valueOf(EVFILT_WRITE), "EVFILT_WRITE");
        mFilterNames.put(Short.valueOf(EVFILT_AIO), "EVFILT_AIO");
        mFilterNames.put(Short.valueOf(EVFILT_VNODE), "EVFILT_VNODE");
        mFilterNames.put(Short.valueOf(EVFILT_PROC), "EVFILT_PROC");
        mFilterNames.put(Short.valueOf(EVFILT_SIGNAL), "EVFILT_SIGNAL");
        mFilterNames.put(Short.valueOf(EVFILT_TIMER), "EVFILT_TIMER");
        mFilterNames.put(Short.valueOf(EVFILT_NETDEV), "EVFILT_NETDEV");
        mFilterNames.put(Short.valueOf(EVFILT_FS), "EVFILT_FS");
        mFilterNames.put(Short.valueOf(EVFILT_LIO), "EVFILT_LIO");
        mFilterNames.put(Short.valueOf(EVFILT_USER), "EVFILT_USER");

        mFlags = new FlagDefinitions();
        mFlags.define(EV_ADD, "EV_ADD");
        mFlags.define(EV_DELETE, "EV_DELETE");
        mFlags.define(EV_ENABLE, "EV_ENABLE");
        mFlags.define(EV_DISABLE, "EV_DISABLE");
        mFlags.define(EV_ONESHOT, "EV_ONESHOT");
        mFlags.define(EV_CLEAR, "EV_CLEAR");
        mFlags.define(EV_RECEIPT, "EV_RECEIPT");
        mFlags.define(EV_DISPATCH, "EV_DISPATCH");
        mFlags.define(EV_SYSFLAGS, "EV_SYSFLAGS");
        mFlags.define(EV_FLAG1, "EV_FLAG1");
        mFlags.define(EV_EOF, "EV_EOF");
        mFlags.define(EV_ERROR, "EV_ERROR");

        mFflags = new HashMap<Integer, FlagDefinitions>();
        FlagDefinitions rwFlags = new FlagDefinitions();
        rwFlags.define(NOTE_LOWAT, "NOTE_LOWAT");
        mFflags.put(Integer.valueOf(EVFILT_READ), rwFlags);
        mFflags.put(Integer.valueOf(EVFILT_WRITE), rwFlags);
        FlagDefinitions vnodeFlags = new FlagDefinitions();
        vnodeFlags.define(NOTE_DELETE, "NOTE_DELETE");
        vnodeFlags.define(NOTE_WRITE, "NOTE_WRITE");
        vnodeFlags.define(NOTE_EXTEND, "NOTE_EXTEND");
        vnodeFlags.define(NOTE_ATTRIB, "NOTE_ATTRIB");
        vnodeFlags.define(NOTE_LINK, "NOTE_LINK");
        vnodeFlags.define(NOTE_RENAME, "NOTE_RENAME");
        vnodeFlags.define(NOTE_REVOKE, "NOTE_REMOVE");
        mFflags.put(Integer.valueOf(EVFILT_VNODE), vnodeFlags);
        FlagDefinitions procFlags = new FlagDefinitions();
        procFlags.define(NOTE_EXIT, "NOTE_EXIT");
        procFlags.define(NOTE_FORK, "NOTE_FORK");
        procFlags.define(NOTE_TRACK, "NOTE_TRACK");
        procFlags.define(NOTE_TRACKERR, "NOTE_TRACKERR");
        procFlags.define(NOTE_CHILD, "NOTE_CHILD");
        mFflags.put(Integer.valueOf(EVFILT_PROC), procFlags);
        FlagDefinitions userFlags = new FlagDefinitions();
        userFlags.define(NOTE_FFNOP, "NOTE_FFNOP");
        userFlags.define(NOTE_FFAND, "NOTE_FFAND");
        userFlags.define(NOTE_FFOR, "NOTE_FFOR");
        userFlags.define(NOTE_FFCOPY, "NOTE_FFCOPY");
        userFlags.define(NOTE_TRIGGER, "NOTE_TRIGGER");
        mFflags.put(Integer.valueOf(EVFILT_USER), userFlags);
        FlagDefinitions empty = new FlagDefinitions();
        int[] noOptionsFlags = { EVFILT_AIO, EVFILT_SIGNAL, EVFILT_TIMER,
                                 EVFILT_NETDEV, EVFILT_FS, EVFILT_LIO };
        for (int i = 0; i < noOptionsFlags.length; i++) {
            mFflags.put(Integer.valueOf(noOptionsFlags[i]), empty);
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
