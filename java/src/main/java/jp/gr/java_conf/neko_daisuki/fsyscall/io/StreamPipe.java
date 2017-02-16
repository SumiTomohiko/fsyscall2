package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.Pipe;

public class StreamPipe {

    private InputStream mIn;
    private OutputStream mOut;

    public StreamPipe() throws IOException {
        Pipe pipe = Pipe.open();
        InputStream in = Channels.newInputStream(pipe.source());
        mIn = new BufferedInputStream(in, 1 * 1024 * 1024);
        mOut = Channels.newOutputStream(pipe.sink());
    }

    public InputStream getInputStream() {
        return mIn;
    }

    public OutputStream getOutputStream() {
        return mOut;
    }
}