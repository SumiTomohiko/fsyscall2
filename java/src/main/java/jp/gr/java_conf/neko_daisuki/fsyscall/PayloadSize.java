package jp.gr.java_conf.neko_daisuki.fsyscall;

public class PayloadSize {

    private int mValue;

    public static PayloadSize fromInteger(int value) {
        return new PayloadSize(value);
    }

    public int toInteger() {
        return mValue;
    }

    public String toString() {
        return Integer.toString(mValue);
    }

    private PayloadSize(int value) {
        mValue = value;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
