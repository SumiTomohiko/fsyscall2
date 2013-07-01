package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.ArrayList;
import java.util.List;

public class Permissions {

    private abstract static class Permission {

        private boolean mAllowed;

        public Permission(boolean allowed) {
            mAllowed = allowed;
        }

        public abstract boolean isMatched(String path);

        public boolean isAllowed() {
            return mAllowed;
        }
    }

    private static class PathPermission extends Permission {

        private String mPath;

        public PathPermission(String path, boolean allowed) {
            super(allowed);
            mPath = path;
        }

        public boolean isMatched(String path) {
            return mPath.equals(path);
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

    public void allowPath(String path) {
        mPermissions.add(new PathPermission(path, true));
    }

    public boolean isAllowed(String path) {
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
