package jp.gr.java_conf.neko_daisuki.fsyscall.util;

public class InvalidPathException extends Exception {

    public InvalidPathException(String message, String path) {
        super(String.format("%s: %s", message, path));
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
