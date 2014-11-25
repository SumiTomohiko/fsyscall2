package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

class Pipe {

    private class StatefulOutputStream extends OutputStream {

        private OutputStream mOut;

        public StatefulOutputStream(PipedOutputStream out) {
            mOut = out;
        }

        @Override
        public void close() throws IOException {
            mOut.close();
            mClosed = true;
        }

        @Override
        public void write(int b) throws IOException {
            mOut.write(b);
        }
    }

    private class StatefulInputStream extends InputStream {

        private InputStream mIn;

        public StatefulInputStream(PipedInputStream in) {
            mIn = in;
        }

        @Override
        public int read() throws IOException {
            return mIn.read();
        }

        /**
         * Returns a number of available bytes. This method throws an
         * IOException when the OutputStream is closed.
         */
        @Override
        public int available() throws IOException {
            int nbytes = mIn.available();
            if ((nbytes == 0) && mClosed) {
                throw new IOException("closed pipe");
            }
            return nbytes;
        }
    }

    private InputStream mIn;
    private OutputStream mOut;
    private boolean mClosed;

    public Pipe() throws IOException {
        PipedInputStream pin = new PipedInputStream();
        PipedOutputStream pout = new PipedOutputStream(pin);
        mIn = new StatefulInputStream(pin);
        mOut = new StatefulOutputStream(pout);
        mClosed = false;
    }

    public InputStream getInputStream() {
        return mIn;
    }

    public OutputStream getOutputStream() {
        return mOut;
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
