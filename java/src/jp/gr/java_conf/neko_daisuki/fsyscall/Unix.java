package jp.gr.java_conf.neko_daisuki.fsyscall;

public class Unix {

    public static class Stat {
    }

    public static class FdSet {
    }

    public static class TimeVal {
    }

    public interface Constants {

        public static final int O_RDONLY = 0x0000;
        public static final int O_WRONLY = 0x0001;
        public static final int O_RDWR = 0x0002;
        public static final int O_ACCMODE = 0x0003;

        public static final int O_CREAT = 0x200;

        public static final int SEEK_SET = 0;
        public static final int SEEK_CUR = 1;
        public static final int SEEK_END = 2;
        public static final int SEEK_DATA = 3;
        public static final int SEEK_HOLE = 4;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
