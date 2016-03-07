package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.util.StringUtil;

public class Unix {

    public static class DirEnt {

        public int d_fileno;
        //public int d_reclen;
        public int d_type;
        //public int d_namelen;
        public String d_name;

        public DirEnt(int fileno, int type, String name) {
            d_fileno = fileno;
            d_type = type;
            d_name = name;
        }

        public DirEnt(int type, String name) {
            this(42, type, name);
        }

        public String toString() {
            String fmt = "DirEnt(d_fileno=%d, d_type=%d (%s), d_name=%s)";
            String type = Constants.DirEnt.toString(d_type);
            String name = StringUtil.quote(d_name);
            return String.format(fmt, d_fileno, d_type, type, name);
        }
    }

    public static class Fdset implements Iterable<Integer> {

        private List<Integer> mFds = new LinkedList<Integer>();

        public void add(int fd) {
            mFds.add(Integer.valueOf(fd));
        }

        public int get(int index) {
            return mFds.get(index).intValue();
        }

        public int size() {
            return mFds.size();
        }

        public Iterator<Integer> iterator() {
            return mFds.iterator();
        }

        public String toString() {
            return String.format("Fdset(%s)", chainStrings(mFds, ",", "empty"));
        }

        public void clear() {
            mFds.clear();
        }
    }

    public static class IoVec {

        public byte[] iov_base;
        public long iov_len;

        public IoVec(byte[] base, long len) {
            iov_base = base;
            iov_len = len;
        }

        public IoVec() {
        }
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

        public Stat(int uid, int gid) {
            st_dev = -1;
            st_uid = uid;
            st_gid = gid;
            st_blksize = 8192;
        }
    }

    public static class TimeZone {

        public int tz_minuteswest;
        public int tz_dsttime;

        public TimeZone(int minuteswest, int dsttime) {
            tz_minuteswest = minuteswest;
            tz_dsttime = dsttime;
        }
    }

    public static class TimeSpec {

        public int tv_sec;
        public long tv_nsec;

        public TimeSpec() {
        }

        public TimeSpec(int sec, long nsec) {
            tv_sec = sec;
            tv_nsec = nsec;
        }

        public String toString() {
            String fmt = "TimeSpec(tv_sec=%d, tv_nsec=%d)";
            return String.format(fmt, tv_sec, tv_nsec);
        }

        public long toNanoTime() {
            return 1000000000L * tv_sec + tv_nsec;
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

        public static class DirEnt {

            private static Map<Integer, String> mTypes;

            public static String toString(int type) {
                if (mTypes == null) {
                    mTypes = new HashMap<Integer, String>();
                    mTypes.put(Integer.valueOf(DT_UNKNOWN), "DT_UNKNOWN");
                    mTypes.put(Integer.valueOf(DT_FIFO), "DT_FIFO");
                    mTypes.put(Integer.valueOf(DT_CHR), "DT_CHR");
                    mTypes.put(Integer.valueOf(DT_DIR), "DT_DIR");
                    mTypes.put(Integer.valueOf(DT_BLK), "DT_BLK");
                    mTypes.put(Integer.valueOf(DT_REG), "DT_REG");
                    mTypes.put(Integer.valueOf(DT_LNK), "DT_LNK");
                    mTypes.put(Integer.valueOf(DT_SOCK), "DT_SOCK");
                    mTypes.put(Integer.valueOf(DT_WHT), "DT_WHT");
                }

                String name = mTypes.get(Integer.valueOf(type));

                return name != null ? name : "invalid";
            }
        }

        public static class Flag {

            private long mMask;
            private String mName;

            public static String toString(Flag[] flags, long n) {
                Collection<String> sa = new LinkedList<String>();
                int length = flags.length;
                for (int i = 0; i < length; i++) {
                    Flag flag = flags[i];
                    if (flag.isMatched(n)) {
                        sa.add(flag.getName());
                    }
                }
                return chainStrings(sa, "|", "nothing");
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

        public static class Wait4 {

            private static final Flag[] FLAGS = {
                new Flag(WNOHANG, "WNOHANG"),
                new Flag(WUNTRACED, "WUNTRACED"),
                new Flag(WCONTINUED, "WCONTINUED"),
                new Flag(WNOWAIT, "WNOWAIT")
            };

            public static String toString(int options) {
                return Flag.toString(FLAGS, options);
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
                new Flag(POLLINIGNEOF, "POLLINIGNEOF"),
                new Flag(POLLERR, "POLLERR"),
                new Flag(POLLHUP, "POLLHUP"),
                new Flag(POLLNVAL, "POLLNVAL")
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

        public static class Open {

            private static final Flag[] FLAGS = {
                new Flag(O_NONBLOCK, "O_NONBLOCK"),
                new Flag(O_APPEND, "O_APPEND"),
                new Flag(O_SHLOCK, "O_SHLOCK"),
                new Flag(O_EXLOCK, "O_EXLOCK"),
                new Flag(O_ASYNC, "O_ASYNC"),
                new Flag(O_FSYNC, "O_FSYNC"),
                new Flag(O_SYNC, "O_SYNC"),
                new Flag(O_NOFOLLOW, "O_NOFOLLOW"),
                new Flag(O_CREAT, "O_CREAT"),
                new Flag(O_TRUNC, "O_TRUNC"),
                new Flag(O_EXCL, "O_EXCL"),
                new Flag(FHASLOCK, "FHASLOCK"),
                new Flag(O_NOCTTY, "O_NOCTTY"),
                new Flag(O_DIRECT, "O_DIRECT"),
                new Flag(O_DIRECTORY, "O_DIRECTORY"),
                new Flag(O_EXEC, "O_EXEC"),
                new Flag(O_TTY_INIT, "O_TTY_INIT"),
                new Flag(O_CLOEXEC, "O_CLOEXEC")
            };

            private static final String[] MODE = {
                "O_RDONLY",
                "O_WRONLY",
                "O_RDWR"
            };

            public static String toString(int flags) {
                String s = MODE[flags & O_ACCMODE];
                int opts = flags & ~O_ACCMODE;
                String t = opts != 0 ? String.format("|%s",
                                                     Flag.toString(FLAGS, opts))
                                     : "";
                return s + t;
            }
        }

        public static class Mode {

            private static final Flag[] FLAGS = {
                new Flag(S_ISUID, "S_ISUID"),
                new Flag(S_ISGID, "S_ISGID"),
                new Flag(S_ISTXT, "S_ISTXT"),
                new Flag(S_IRUSR, "S_IRUSR"),
                new Flag(S_IWUSR, "S_IWUSR"),
                new Flag(S_IXUSR, "S_IXUSR"),
                new Flag(S_IRGRP, "S_IRGRP"),
                new Flag(S_IWGRP, "S_IWGRP"),
                new Flag(S_IXGRP, "S_IXGRP"),
                new Flag(S_IROTH, "S_IROTH"),
                new Flag(S_IWOTH, "S_IWOTH"),
                new Flag(S_IXOTH, "S_IXOTH"),
                new Flag(S_IFIFO, "S_IFIFO"),
                new Flag(S_IFCHR, "S_IFCHR"),
                new Flag(S_IFDIR, "S_IFDIR"),
                new Flag(S_IFBLK, "S_IFBLK"),
                new Flag(S_IFREG, "S_IFREG"),
                new Flag(S_IFLNK, "S_IFLNK"),
                new Flag(S_IFSOCK, "S_IFSOCK"),
                new Flag(S_ISVTX, "S_ISVTX"),
                new Flag(S_IFWHT, "S_IFWHT")
            };

            public static String toString(int flags) {
                return Flag.toString(FLAGS, flags);
            }
        }

        public static final int O_RDONLY = 0x0000;
        public static final int O_WRONLY = 0x0001;
        public static final int O_RDWR = 0x0002;
        public static final int O_ACCMODE = 0x0003;

        public static final int O_NONBLOCK = 0x0004;
        public static final int O_APPEND = 0x0008;
        public static final int O_SHLOCK = 0x0010;
        public static final int O_EXLOCK = 0x0020;
        public static final int O_ASYNC = 0x0040;
        public static final int O_FSYNC = 0x0080;
        public static final int O_SYNC = 0x0080;
        public static final int O_NOFOLLOW = 0x0100;
        public static final int O_CREAT = 0x0200;
        public static final int O_TRUNC = 0x0400;
        public static final int O_EXCL = 0x0800;
        public static final int FHASLOCK = 0x4000;
        public static final int O_NOCTTY = 0x8000;
        public static final int O_DIRECT = 0x00010000;
        public static final int O_DIRECTORY = 0x00020000;
        public static final int O_EXEC = 0x00040000;
        public static final int O_TTY_INIT = 0x00080000;
        public static final int O_CLOEXEC = 0x00100000;

        public static final int SEEK_SET = 0;
        public static final int SEEK_CUR = 1;
        public static final int SEEK_END = 2;
        public static final int SEEK_DATA = 3;
        public static final int SEEK_HOLE = 4;

        public static final int AF_LOCAL = 1;
        public static final int AF_UNIX = AF_LOCAL;

        public static final int PF_LOCAL = AF_LOCAL;
        public static final int PF_UNIX = PF_LOCAL;

        public static final int SOCK_STREAM = 1;

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
        public static final int POLLERR = 0x0008;
        public static final int POLLHUP = 0x0010;
        public static final int POLLNVAL = 0x0020;

        public static final int S_ISUID = 0004000;
        public static final int S_ISGID = 0002000;
        public static final int S_ISTXT = 0001000;
        public static final int S_IRWXU = 0000700;
        public static final int S_IRUSR = 0000400;
        public static final int S_IWUSR = 0000200;
        public static final int S_IXUSR = 0000100;
        public static final int S_IRWXG = 0000070;
        public static final int S_IRGRP = 0000040;
        public static final int S_IWGRP = 0000020;
        public static final int S_IXGRP = 0000010;
        public static final int S_IRWXO = 0000007;
        public static final int S_IROTH = 0000004;
        public static final int S_IWOTH = 0000002;
        public static final int S_IXOTH = 0000001;
        public static final int ACCESSPERMS = S_IRWXU | S_IRWXG | S_IRWXO;
        public static final int S_IFMT = 0170000;
        public static final int S_IFIFO = 0010000;
        public static final int S_IFCHR = 0020000;
        public static final int S_IFDIR = 0040000;
        public static final int S_IFBLK = 0060000;
        public static final int S_IFREG = 0100000;
        public static final int S_IFLNK = 0120000;
        public static final int S_IFSOCK = 0140000;
        public static final int S_ISVTX = 0001000;
        public static final int S_IFWHT = 0160000;

        public static final int SIG_BLOCK = 1;
        public static final int SIG_UNBLOCK = 2;
        public static final int SIG_SETMASK = 3;

        public static final int SOL_SOCKET = 0xffff;

        public static final int SCM_RIGHTS = 0x01;
        public static final int SCM_TIMESTAMP = 0x02;
        public static final int SCM_CREDS = 0x03;
        public static final int SCM_BINTIME = 0x04;

        public static final int DT_UNKNOWN = 0;
        public static final int DT_FIFO = 1;
        public static final int DT_CHR = 2;
        public static final int DT_DIR = 4;
        public static final int DT_BLK = 6;
        public static final int DT_REG = 8;
        public static final int DT_LNK = 10;
        public static final int DT_SOCK = 12;
        public static final int DT_WHT = 14;

        public static final int WNOHANG = 1;
        public static final int WUNTRACED = 2;
        public static final int WSTOPPED = WUNTRACED;
        public static final int WCONTINUED = 4;
        public static final int WNOWAIT = 8;
    }

    public abstract static class Cmsgdata {

        public abstract Cmsgdata copy();
    }

    public static class Cmsgfds extends Cmsgdata {

        public int[] fds;

        public Cmsgfds(int[] fds) {
            this.fds = fds;
        }

        public Cmsgfds(int nfds) {
            this(new int[nfds]);
        }

        public Cmsgdata copy() {
            int len = this.fds.length;
            int[] fds = new int[len];
            for (int i = 0; i < len; i++) {
                fds[i] = this.fds[i];
            }
            return new Cmsgfds(fds);
        }

        public String toString() {
            Collection<Integer> c = new LinkedList<Integer>();
            int len = this.fds.length;
            for (int i = 0; i < len; i++) {
                c.add(Integer.valueOf(this.fds[i]));
            }
            return String.format("Cmsgfds([%s])", chainStrings(c, ",", ""));
        }
    }

    public static class Cmsgcred extends Cmsgdata {

        public Pid cmcred_pid;
        public int cmcred_uid;
        public int cmcred_euid;
        public int cmcred_gid;
        /*
         * cmcred_ngroups is unused.
         */
        //public int cmcred_ngroups;
        public int[] cmcred_groups;

        public Cmsgcred(Pid pid, int uid, int euid, int gid, int[] groups) {
            cmcred_pid = pid;
            cmcred_uid = uid;
            cmcred_euid = euid;
            cmcred_gid = gid;
            cmcred_groups = groups;
        }

        public Cmsgdata copy() {
            int len = cmcred_groups.length;
            int[] groups = new int[len];
            for (int i = 0; i < len; i++) {
                groups[i] = cmcred_groups[i];
            }
            return new Cmsgcred(cmcred_pid, cmcred_uid, cmcred_euid, cmcred_gid,
                                groups);
        }

        public String toString() {
            String fmt = "Cmsgcred(pid=%s, uid=%d, euid=%d, gid=%d, groups=%s)";
            int ngroups = cmcred_groups.length;
            String s = 0 < ngroups ? Integer.toString(cmcred_groups[0]) : "";
            StringBuilder buffer = new StringBuilder(s);
            for (int i = 1; i < ngroups; i++) {
                buffer.append(",");
                buffer.append(Integer.toString(cmcred_groups[i]));
            }
            return String.format(fmt, cmcred_pid, cmcred_uid, cmcred_euid,
                                 cmcred_gid, buffer);
        }
    }

    public static class Cmsghdr {

        /*
         * architecture dependent. unused.
         */
        //public int cmsg_len;
        public int cmsg_level;
        public int cmsg_type;
        public Cmsgdata cmsg_data;

        public Cmsghdr(int level, int type, Cmsgdata data) {
            cmsg_level = level;
            cmsg_type = type;
            cmsg_data = data;
        }

        public Cmsghdr(Cmsghdr cmsghdr) {
            cmsg_level = cmsghdr.cmsg_level;
            cmsg_type = cmsghdr.cmsg_type;
            Cmsgdata data = cmsghdr.cmsg_data;
            cmsg_data = data != null ? data.copy() : null;
        }

        public String toString() {
            String fmt = "Cmsghdr(cmsg_level=%d (%s), cmsg_type=%d (%s), cmsg_data=%s)";
            String level;
            String type;
            switch (cmsg_level) {
            case Constants.SOL_SOCKET:
                level = "SOL_SOCKET";
                switch (cmsg_type) {
                case Constants.SCM_CREDS:
                    type = "SCM_CREDS";
                    break;
                case Constants.SCM_RIGHTS:
                    type = "SCM_RIGHTS";
                    break;
                default:
                    type = "unknown";
                    break;
                }
                break;
            default:
                level = type = "unknown";
                break;
            }
            return String.format(fmt, cmsg_level, level, cmsg_type, type,
                                 cmsg_data);
        }
    }

    public static class Msghdr {

        /*
         * not supported.
         */
        //public SocketAddress msg_name;

        /*
         * architecture dependent. unused.
         */
        //public int msg_namelen;

        public IoVec[] msg_iov;

        /*
         * unused.
         */
        //public int msg_iovlen;

        public Cmsghdr[] msg_control;

        /*
         * architecture dependent. unused.
         */
        //public int msg_controllen;

        public int msg_flags;

        public Msghdr(IoVec[] iov, Cmsghdr[] control, int flags) {
            msg_iov = iov;
            msg_control = control;
            msg_flags = flags;
        }

        public String toString() {
            String fmt = "Msghdr(msg_iovlen=%d, msg_control=%s, msg_flags=%d)";

            String cntlstr;
            if (msg_control != null) {
                Collection<Cmsghdr> c = new LinkedList<Cmsghdr>();
                int len = msg_control.length;
                for (int i = 0; i < len; i++) {
                    c.add(msg_control[i]);
                }
                cntlstr = String.format("[%s]", chainStrings(c, ",", ""));
            }
            else {
                cntlstr = "null";
            }

            return String.format(fmt, msg_iov.length, cntlstr, msg_flags);
        }
    }

    public static final int _WSTOPPED = 0177;

    public static int W_EXITCODE(int ret, int sig) {
        return (ret << 8) | sig;
    }

    public static int W_STOPCODE(int sig) {
        return (sig << 8) | _WSTOPPED;
    }

    private static String chainStrings(Collection c, String sep,
                                       String nothing) {
        String s = "";
        StringBuilder builder = new StringBuilder();
        for (Object o: c) {
            builder.append(s);
            builder.append(o != null ? o.toString() : "null");
            s = sep;
        }
        return 0 < builder.length() ? builder.toString() : nothing;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
