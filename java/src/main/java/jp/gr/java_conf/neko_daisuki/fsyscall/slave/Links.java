package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.HashMap;
import java.util.Map;

public class Links {

    private Map<String, String> mMap;

    public Links() {
        mMap = new HashMap<String, String>();
    }

    public void put(String dest, String src) {
        mMap.put(src, dest);
    }

    public String get(String path) {
        String dest = mMap.get(path);
        return dest != null ? dest : path;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
