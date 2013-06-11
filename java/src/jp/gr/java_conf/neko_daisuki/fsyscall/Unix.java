package jp.gr.java_conf.neko_daisuki.fsyscall;

public interface Unix {

    public static class IoVec {

        public byte[] iov_base;
        public long iov_len;
    }

    public static class Stat {

        public int st_dev;
        public int st_ino;
        public int st_mode;
        public int st_nlink;
        public int st_uid;
        public int st_gid;
        public int st_rdev;
        public long st_size;
        public long st_blocks;
        public int st_blksize;
        public int st_flags;
        public int st_gen;
        public int st_lspare;
    }

    public static class TimeVal {

        public long tv_sec;
        public long tv_usec;
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
