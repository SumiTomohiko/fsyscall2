package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.ArrayList;
import java.util.List;

import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.NormalizedPath;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.StringUtil;

public class Permissions {

    private abstract static class Permission {

        private boolean mAllowed;

        public Permission(boolean allowed) {
            mAllowed = allowed;
        }

        public abstract boolean isMatched(NormalizedPath path);
        public abstract String represent();

        public boolean isAllowed() {
            return mAllowed;
        }
    }

    private static class PathPermission extends Permission {

        private NormalizedPath mPath;

        public PathPermission(NormalizedPath path, boolean allowed) {
            super(allowed);
            mPath = path;
        }

        public boolean isMatched(NormalizedPath path) {
            return mPath.equals(path);
        }

        public String represent() {
            return mPath.toString();
        }
    }

    private static class DirectoryPermission extends Permission {

        private String mDirPath;

        public DirectoryPermission(NormalizedPath dirPath, boolean allowed) {
            super(allowed);
            mDirPath = dirPath.toString() + "/";
        }

        public boolean isMatched(NormalizedPath path) {
            return path.toString().startsWith(mDirPath);
        }

        public String represent() {
            return String.format("%s**", mDirPath);
        }
    }

    private static Logging.Logger mLogger;

    private List<Permission> mPermissions;
    private boolean mDefault;

    public Permissions() {
        initialize(false);
    }

    public Permissions(boolean default_) {
        initialize(default_);
    }

    public void allowPath(NormalizedPath path) {
        mPermissions.add(new PathPermission(path, true));
    }

    public void allowDirectoryContents(NormalizedPath dirPath) {
        mPermissions.add(new DirectoryPermission(dirPath, true));
    }

    public boolean isAllowed(NormalizedPath path) {
        for (Permission p: mPermissions) {
            if (p.isMatched(path)) {
                boolean allowed = p.isAllowed();
                String fmt = "matched: %s: %s %s";
                String s = allowed ? "accepted" : "rejected";
                String msg = String.format(fmt, p.represent(),
                                           StringUtil.quote(path.toString()),
                                           s);
                mLogger.info(msg);
                return allowed;
            }
        }
        return mDefault;
    }

    private void initialize(boolean default_) {
        mDefault = default_;
        mPermissions = new ArrayList<Permission>();
    }

    static {
        mLogger = new Logging.Logger("Permissions");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
