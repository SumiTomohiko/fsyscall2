package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class KEventArray implements Iterable<KEvent> {

    private class Itor implements Iterator<KEvent> {

        private int mPosition;

        public boolean hasNext() {
            return mPosition < mArray.length;
        }

        public KEvent next() {
            KEvent kev;
            try {
                kev = mArray[mPosition];
            }
            catch (ArrayIndexOutOfBoundsException unused) {
                throw new NoSuchElementException();
            }
            mPosition++;
            return kev;
        }

        public void remove() {
            // does nothing.
        }
    }

    private KEvent[] mArray;

    public KEventArray(int size) {
        mArray = new KEvent[size];
        for (int i = 0; i < size; i++) {
            mArray[i] = new KEvent();
        }
    }

    public Iterator<KEvent> iterator() {
        return new Itor();
    }

    public KEvent get(int pos) {
        return mArray[pos];
    }

    public String toString() {
        StringBuilder buffer = new StringBuilder("[");
        int len = mArray.length;
        for (int i = 0; i < len; i++) {
            buffer.append(i == 0 ? "" : ",");
            buffer.append(mArray[i].toString());
        }
        buffer.append("]");

        return buffer.toString();
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
