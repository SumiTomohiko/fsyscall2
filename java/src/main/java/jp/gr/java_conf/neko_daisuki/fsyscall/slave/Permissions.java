package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.ArrayList;
import java.util.List;

import jp.gr.java_conf.neko_daisuki.fsyscall.util.NormalizedPath;

public class Permissions {

    private abstract static class Permission {

        private boolean mAllowed;

        public Permission(boolean allowed) {
            mAllowed = allowed;
        }

        public abstract boolean isMatched(NormalizedPath path);

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
    }

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
                return p.isAllowed();
            }
        }
        return mDefault;
    }

    private void initialize(boolean default_) {
        mDefault = default_;
        mPermissions = new ArrayList<Permission>();
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
