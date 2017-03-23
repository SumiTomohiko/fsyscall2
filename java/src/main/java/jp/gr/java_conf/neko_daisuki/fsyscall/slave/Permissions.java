package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.ArrayList;
import java.util.List;

import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.PhysicalPath;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.StringUtil;

public class Permissions {

    private abstract static class Permission {

        private boolean mAllowed;

        public Permission(boolean allowed) {
            mAllowed = allowed;
        }

        public abstract boolean isMatched(PhysicalPath path);
        public abstract String represent();

        public boolean isAllowed() {
            return mAllowed;
        }
    }

    private static class PathPermission extends Permission {

        private PhysicalPath mPath;

        public PathPermission(PhysicalPath path, boolean allowed) {
            super(allowed);
            mPath = path;
        }

        public boolean isMatched(PhysicalPath path) {
            return mPath.equals(path);
        }

        public String represent() {
            return mPath.toString();
        }
    }

    private static class DirectoryPermission extends Permission {

        private String mDirPath;

        public DirectoryPermission(PhysicalPath dirPath, boolean allowed) {
            super(allowed);
            mDirPath = dirPath.toString() + "/";
        }

        public boolean isMatched(PhysicalPath path) {
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

    public void allowPath(PhysicalPath path) {
        mPermissions.add(new PathPermission(path, true));
    }

    public void allowDirectoryContents(PhysicalPath dirPath) {
        mPermissions.add(new DirectoryPermission(dirPath, true));
    }

    public boolean isAllowed(PhysicalPath path) {
        for (Permission p: mPermissions) {
            if (p.isMatched(path)) {
                boolean allowed = p.isAllowed();
                mLogger.info("matched: %s: %s %s",
                             p.represent(), StringUtil.quote(path.toString()),
                             allowed ? "accepted" : "rejected");
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
