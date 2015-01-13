package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.LinkedList;
import java.util.List;

public class Unix {

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

    public static class TimeZone {

        public int tz_minuteswest;
        public int tz_dsttime;

        public TimeZone(int minuteswest, int dsttime) {
            tz_minuteswest = minuteswest;
            tz_dsttime = dsttime;
        }
    }

    public static class TimeVal {

        public long tv_sec;
        public long tv_usec;

        public TimeVal(long sec, long usec) {
            tv_sec = sec;
            tv_usec = usec;
        }

        public TimeVal() {
        }

        public String toString() {
            String fmt = "TimeVal(tv_sec=%d, tv_usec=%d)";
            return String.format(fmt, tv_sec, tv_usec);
        }
    }

    public static class Rusage {

        public TimeVal ru_utime = new TimeVal();
        public TimeVal ru_stime = new TimeVal();
        public long ru_maxrss;
        public long ru_ixrss;
        public long ru_idrss;
        public long ru_isrss;
        public long ru_minflt;
        public long ru_majflt;
        public long ru_nswap;
        public long ru_inblock;
        public long ru_oublock;
        public long ru_msgsnd;
        public long ru_msgrcv;
        public long ru_nsignals;
        public long ru_nvcsw;
        public long ru_nivcsw;

        public String toString() {
            StringBuilder buffer = new StringBuilder("Rusage(");
            buffer.append(String.format("ru_utime=%s, ", ru_utime));
            buffer.append(String.format("ru_stime=%s, ", ru_stime));
            buffer.append(String.format("ru_maxrss=%d, ", ru_maxrss));
            buffer.append(String.format("ru_ixrss=%d, ", ru_ixrss));
            buffer.append(String.format("ru_idrss=%d, ", ru_idrss));
            buffer.append(String.format("ru_isrss=%d, ", ru_isrss));
            buffer.append(String.format("ru_minflt=%d, ", ru_minflt));
            buffer.append(String.format("ru_majflt=%d, ", ru_majflt));
            buffer.append(String.format("ru_nswap=%d, ", ru_nswap));
            buffer.append(String.format("ru_inblock=%d, ", ru_inblock));
            buffer.append(String.format("ru_oublock=%d, ", ru_oublock));
            buffer.append(String.format("ru_msgsnd=%d, ", ru_msgsnd));
            buffer.append(String.format("ru_msgrcv=%d, ", ru_msgrcv));
            buffer.append(String.format("ru_nsignals=%d, ", ru_nsignals));
            buffer.append(String.format("ru_nsignals=%d, ", ru_nsignals));
            buffer.append(String.format("ru_nvcsw=%d, ", ru_nvcsw));
            buffer.append(String.format("ru_nivcsw=%d)", ru_nivcsw));
            return buffer.toString();
        }
    }

    public interface Constants {

        public static class Flag {

            private long mMask;
            private String mName;

            public static String toString(Flag[] flags, long n) {
                List<String> sa = new LinkedList<String>();
                int length = flags.length;
                for (int i = 0; i < length; i++) {
                    Flag flag = flags[i];
                    if (flag.isMatched(n)) {
                        sa.add(flag.getName());
                    }
                }
                int size = sa.size();
                if (size == 0) {
                    return "";
                }
                StringBuilder builder = new StringBuilder(sa.get(0));
                for (int i = 1; i < size; i++) {
                    builder.append("|");
                    builder.append(sa.get(i));
                }
                return builder.toString();
            }

            public Flag(long mask, String name) {
                mMask = mask;
                mName = name;
            }

            private String getName() {
                return mName;
            }

            private boolean isMatched(long n) {
                return (n & mMask) != 0;
            }
        }

        public static class Poll {

            private static final Flag[] FLAGS = {
                new Flag(POLLIN, "POLLIN"),
                new Flag(POLLPRI, "POLLPRI"),
                new Flag(POLLOUT, "POLLOUT"),
                new Flag(POLLRDNORM, "POLLRDNORM"),
                //new Flag(POLLWRNORM, "POLLWRNORM"),
                new Flag(POLLRDBAND, "POLLRDBAND"),
                new Flag(POLLWRBAND, "POLLWRBAND"),
                new Flag(POLLINIGNEOF, "POLLINIGNEOF")
            };

            public static String toString(int events) {
                return Flag.toString(FLAGS, events);
            }
        }

        public static class Fsetfl {

            private static final Flag[] FLAGS = {
                new Flag(O_NONBLOCK, "O_NONBLOCK"),
                new Flag(O_APPEND, "O_APPEND"),
                new Flag(O_ASYNC, "O_ASYNC"),
                new Flag(O_DIRECT, "O_DIRECT")
            };

            public static String toString(long arg) {
                return Flag.toString(FLAGS, arg);
            }
        }

        public static final int O_RDONLY = 0x0000;
        public static final int O_WRONLY = 0x0001;
        public static final int O_RDWR = 0x0002;
        public static final int O_ACCMODE = 0x0003;
        public static final int O_CREAT = 0x200;

        public static final int O_NONBLOCK = 0x0004;
        public static final int O_APPEND = 0x0008;
        public static final int O_ASYNC = 0x0040;
        public static final int O_DIRECT = 0x00010000;

        public static final int SEEK_SET = 0;
        public static final int SEEK_CUR = 1;
        public static final int SEEK_END = 2;
        public static final int SEEK_DATA = 3;
        public static final int SEEK_HOLE = 4;

        public static final int AF_LOCAL = 1;
        public static final int AF_UNIX = AF_LOCAL;

        public static final int PF_LOCAL = AF_LOCAL;
        public static final int PF_UNIX = PF_LOCAL;

        public static final int F_DUPFD = 0;
        public static final int F_GETFD = 1;
        public static final int F_SETFD = 2;
        public static final int F_GETFL = 3;
        public static final int F_SETFL = 4;
        public static final int F_GETOWN = 5;
        public static final int F_SETOWN = 6;
        public static final int F_OGETLK = 7;
        public static final int F_OSETLK = 8;
        public static final int F_OSETLKW = 9;
        public static final int F_DUP2FD = 10;
        public static final int F_GETLK = 11;
        public static final int F_SETLK = 12;
        public static final int F_SETLKW = 13;
        public static final int F_SETLK_REMOTE = 14;
        public static final int F_READAHEAD = 15;
        public static final int F_RDAHEAD = 16;

        public static final int FD_CLOEXEC = 1;

        public static final int F_RDLCK = 1;
        public static final int F_UNLCK = 2;
        public static final int F_WRLCK = 3;
        public static final int F_UNLCKSYS = 4;
        public static final int F_CANCEL = 5;
        public static final int F_WAIT = 0x010;
        public static final int F_FLOCK = 0x020;
        public static final int F_POSIX = 0x040;
        public static final int F_REMOTE = 0x080;
        public static final int F_NOINTR = 0x100;

        public static final int INFTIM = -1;

        public static final int POLLIN = 0x0001;
        public static final int POLLPRI = 0x0002;
        public static final int POLLOUT = 0x0004;
        public static final int POLLRDNORM = 0x0040;
        public static final int POLLWRNORM = POLLOUT;
        public static final int POLLRDBAND = 0x0080;
        public static final int POLLWRBAND = 0x0100;
        public static final int POLLINIGNEOF = 0x2000;
    }

    public static final int _WSTOPPED = 0177;

    public static int W_EXITCODE(int ret, int sig) {
        return (ret << 8) | sig;
    }

    public static int W_STOPCODE(int sig) {
        return (sig << 8) | _WSTOPPED;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */