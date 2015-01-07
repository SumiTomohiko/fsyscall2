package jp.gr.java_conf.neko_daisuki.fsyscall;

/**
 * Pair Id. This is different from Pid.
 */
public class PairId {

    private int mId;

    public PairId(int id) {
        mId = id;
    }

    @Override
    public int hashCode() {
        return Integer.valueOf(mId).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        PairId pairId;
        try {
            pairId = (PairId)obj;
        }
        catch (ClassCastException e) {
            return false;
        }
        return mId == pairId.mId;
    }

    @Override
    public String toString() {
        return Integer.toString(mId);
    }

    public int toInteger() {
        return mId;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
