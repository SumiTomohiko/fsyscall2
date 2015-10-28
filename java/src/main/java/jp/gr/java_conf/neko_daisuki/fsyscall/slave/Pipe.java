package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;

/**
 * Pipe implementation. Sometimes PipedInputStream.read() was paused (I guess
 * that this is problem of wait()/notifyAll()). So I reimplemented it.
 */
class Pipe {

    private static class Buffer {

        private static class Chunk {

            private int mFrom;
            private int mTo;
            private byte[] mBuffer = new byte[8192];

            public int write(byte[] buffer, int offset) {
                int len = Math.min(buffer.length - offset,
                                   mBuffer.length - mTo);
                System.arraycopy(buffer, offset, mBuffer, mTo, len);
                mTo += len;
                return len;
            }

            public int read(byte[] buffer, int offset) {
                int len = Math.min(buffer.length - offset, mTo - mFrom);
                System.arraycopy(mBuffer, mFrom, buffer, offset, len);
                mFrom += len;
                return len;
            }

            public int read() {
                if (mTo <= mFrom) {
                    return -1;
                }
                byte b = mBuffer[mFrom];
                mFrom++;
                return 0 <= b ? b : 256 + b;
            }

            public boolean isDead() {
                return mBuffer.length <= mFrom;
            }

            public int available() {
                return mTo - mFrom;
            }

            public String toString() {
                String fmt = "Pipe.Buffer.Chunk(length=%d, from=%d, to=%d)";
                return String.format(fmt, mBuffer.length, mFrom, mTo);
            }
        }

        private static final class DummyChunk extends Chunk {

            @Override
            public int write(byte[] buffer, int offset) {
                return 0;
            }

            @Override
            public int read(byte[] buffer, int offset) {
                return 0;
            }
        }

        private static final Chunk DUMMY_CHUNK = new DummyChunk();

        private List<Chunk> mChunks = new LinkedList<Chunk>();

        public void write(byte[] buffer) {
            synchronized (this) {
                int nWrote = getLastChunk().write(buffer, 0);
                int len = buffer.length;
                while (nWrote < len) {
                    Chunk chunk = new Chunk();
                    nWrote += chunk.write(buffer, nWrote);
                    mChunks.add(chunk);
                }
                notifyAll();
            }
        }

        public int read(byte[] buffer, int offset, int len) throws InterruptedException {
            int nRead = 0;
            synchronized (this) {
                while (!isReadable()) {
                    wait();
                }

                while ((nRead < len) && isReadable()) {
                    nRead += mChunks.get(0).read(buffer, offset + nRead);
                    removeFirstChunkIfDead();
                }
            }
            return nRead;
        }

        public int read() throws InterruptedException {
            int b;
            synchronized (this) {
                while (!isReadable()) {
                    wait();
                }

                b = mChunks.get(0).read();
                removeFirstChunkIfDead();
            }
            return b;
        }

        public int available() {
            int nBytes = 0;
            synchronized (this) {
                for (Chunk chunk: mChunks) {
                    nBytes += chunk.available();
                }
            }
            return nBytes;
        }

        private void removeFirstChunkIfDead() {
            if (mChunks.get(0).isDead()) {
                mChunks.remove(0);
            }
        }

        private boolean isReadable() {
            return (0 < mChunks.size()) && (0 < mChunks.get(0).available());
        }

        private Chunk getLastChunk() {
            int size = mChunks.size();
            return 0 < size ? mChunks.get(size - 1) : DUMMY_CHUNK;
        }
    }

    private class PipeOutputStream extends OutputStream {

        @Override
        public void close() throws IOException {
            mClosed = true;
        }

        @Override
        public void write(int b) throws IOException {
            mBuffer.write(new byte[] { (byte)b });
        }
    }

    private class PipeInputStream extends InputStream {

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            try {
                return mBuffer.read(b, off, len);
            }
            catch (InterruptedException unused) {
                throw new InterruptedIOException();
            }
        }

        @Override
        public int read() throws IOException {
            try {
                return mBuffer.read();
            }
            catch (InterruptedException unused) {
                throw new InterruptedIOException();
            }
        }

        /**
         * Returns a number of available bytes. This method throws an
         * IOException when the OutputStream is closed.
         */
        @Override
        public int available() throws IOException {
            int nbytes = mBuffer.available();
            if ((nbytes == 0) && mClosed) {
                throw new IOException("closed pipe");
            }
            return nbytes;
        }
    }

    private Buffer mBuffer = new Buffer();
    private boolean mClosed;
    private InputStream mIn;
    private OutputStream mOut;

    public Pipe() throws IOException {
        mIn = new PipeInputStream();
        mOut = new PipeOutputStream();
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
