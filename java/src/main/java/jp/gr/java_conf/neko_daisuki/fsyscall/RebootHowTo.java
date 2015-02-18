package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.Map;
import java.util.HashMap;

public class RebootHowTo {

    public static final RebootHowTo RB_AUTOBOOT = new RebootHowTo(
            0,
            "RB_AUTOBOOT");
    public static final RebootHowTo RB_ASKNAME = new RebootHowTo(
            0x001,
            "RB_ASKNAME");
    public static final RebootHowTo RB_SINGLE = new RebootHowTo(
            0x002,
            "RB_SINGLE");
    public static final RebootHowTo RB_NOSYNC = new RebootHowTo(
            0x004,
            "RB_NOSYNC");
    public static final RebootHowTo RB_HALT = new RebootHowTo(
            0x008,
            "RB_HALT");
    public static final RebootHowTo RB_INITNAME = new RebootHowTo(
            0x010,
            "RB_INITNAME");
    public static final RebootHowTo RB_DFLTROOT = new RebootHowTo(
            0x020,
            "RB_DFLTROOT");
    public static final RebootHowTo RB_KDB = new RebootHowTo(
            0x040,
            "RB_KDB");
    public static final RebootHowTo RB_RDONLY = new RebootHowTo(
            0x080,
            "RB_RDONLY");
    public static final RebootHowTo RB_DUMP = new RebootHowTo(
            0x100,
            "RB_DUMP");
    public static final RebootHowTo RB_MINIROOT = new RebootHowTo(
            0x200,
            "RB_MINIROOT");
    public static final RebootHowTo RB_VERBOSE = new RebootHowTo(
            0x800,
            "RB_VERBOSE");
    public static final RebootHowTo RB_SERIAL = new RebootHowTo(
            0x1000,
            "RB_SERIAL");
    public static final RebootHowTo RB_CDROM = new RebootHowTo(
            0x2000,
            "RB_CDROM");
    public static final RebootHowTo RB_POWEROFF = new RebootHowTo(
            0x4000,
            "RB_POWEROFF");
    public static final RebootHowTo RB_GDB = new RebootHowTo(
            0x8000,
            "RB_GDB");
    public static final RebootHowTo RB_MUTE = new RebootHowTo(
            0x10000,
            "RB_MUTE");
    public static final RebootHowTo RB_SELFTEST = new RebootHowTo(
            0x20000,
            "RB_SELFTEST");
    public static final RebootHowTo RB_RESERVED1 = new RebootHowTo(
            0x40000,
            "RB_RESERVED1");
    public static final RebootHowTo RB_RESERVED2 = new RebootHowTo(
            0x80000,
            "RB_RESERVED2");
    public static final RebootHowTo RB_PAUSE = new RebootHowTo(
            0x100000,
            "RB_PAUSE");
    public static final RebootHowTo RB_MULTIPLE = new RebootHowTo(
            0x20000000,
            "RB_MULTIPLE");
    public static final RebootHowTo RB_BOOTINFO = new RebootHowTo(
            0x80000000,
            "RB_BOOTINFO");

    private static final Map<Integer, RebootHowTo> mOptions;

    private String mName;
    private int mValue;

    private RebootHowTo(int value, String name) {
        mName = name;
        mValue = value;
    }

    @Override
    public int hashCode() {
        return Integer.valueOf(mValue).hashCode();
    }

    @Override
    public boolean equals(Object o) {
        RebootHowTo howto;
        try {
            howto = (RebootHowTo)o;
        }
        catch (ClassCastException unused) {
            return false;
        }
        return mValue == howto.mValue;
    }

    public String toString() {
        return mName;
    }

    public static RebootHowTo valueOf(int value) {
        return mOptions.get(Integer.valueOf(value));
    }

    static {
        mOptions = new HashMap<Integer, RebootHowTo>();

        RebootHowTo[] options = {
            RB_AUTOBOOT, RB_ASKNAME, RB_SINGLE, RB_NOSYNC, RB_HALT, RB_INITNAME,
            RB_DFLTROOT, RB_KDB, RB_RDONLY, RB_DUMP, RB_MINIROOT, RB_VERBOSE,
            RB_SERIAL, RB_CDROM, RB_POWEROFF, RB_GDB, RB_MUTE, RB_SELFTEST,
            RB_RESERVED1, RB_RESERVED2, RB_PAUSE, RB_MULTIPLE, RB_BOOTINFO };
        int len = options.length;
        for (int i = 0; i < len; i++) {
            RebootHowTo option = options[i];
            mOptions.put(Integer.valueOf(option.mValue), option);
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
