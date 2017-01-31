package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Pipe;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import jp.gr.java_conf.neko_daisuki.fsyscall.Logging;

public class SSLFrontEnd {

    private static class Worker implements Runnable {

        private interface ChannelHandler {

            public void handle() throws IOException;
        }

        private class SocketHandler implements ChannelHandler {

            public void handle() throws IOException {
                mPeerNetData.compact();
                if (!mPeerNetData.hasRemaining()) {
                    SSLSession session = mEngine.getSession();
                    int netBufSize = session.getPacketBufferSize();
                    mPeerNetData = enlargeBuffer(mPeerNetData, netBufSize);
                }

                int nBytes;
                try {
                    nBytes = mSocket.read(mPeerNetData);
                    if (nBytes == -1) {
                        String message = "-1 at SocketChannel.read()";
                        throw new IOException(message);
                    }
                }
                catch (IOException e) {
                    mLogger.info(e);
                    closeSocket();
                    return;
                }
                finally {
                    mPeerNetData.flip();
                }
                mPeerNetDataAvailable = true;
            }
        }

        private class SourceHandler implements ChannelHandler {

            public void handle() throws IOException {
                mMyAppData.compact();
                if (!mMyAppData.hasRemaining()) {
                    SSLSession session = mEngine.getSession();
                    int appBufSize = session.getApplicationBufferSize();
                    mMyAppData = enlargeBuffer(mMyAppData, appBufSize);
                }

                int nBytes;
                try {
                    nBytes = mSource.read(mMyAppData);
                    if (nBytes == -1) {
                        String message = "-1 at Pipe.SourceChannel.read()";
                        throw new IOException(message);
                    }
                }
                catch (IOException e) {
                    mLogger.info(e);
                    closeSource();
                    return;
                }
                finally {
                    mMyAppData.flip();
                }
            }
        }

        private enum ToDo {
            WRAP,
            UNWRAP,
            TASK,
            SELECT
        }

        private Selector mSelector;
        private Selector mHandshakeSelector;
        private SocketChannel mSocket;
        private Pipe.SourceChannel mSource;
        private Pipe.SinkChannel mSink;

        private SSLEngine mEngine;
        private ByteBuffer mMyAppData;
        private ByteBuffer mMyNetData;
        private ByteBuffer mPeerAppData;
        private ByteBuffer mPeerNetData;
        private boolean mPeerNetDataAvailable = false;

        public Worker(SSLContext context, SocketChannel socket,
                      Pipe.SourceChannel source,
                      Pipe.SinkChannel sink) throws IOException {
            mEngine = context.createSSLEngine();
            mEngine.setUseClientMode(true);

            mSelector = Selector.open();
            mHandshakeSelector = Selector.open();
            int op = SelectionKey.OP_READ;
            mSocket = socket;
            mSocket.configureBlocking(false);
            Object attachment = new SocketHandler();
            mSocket.register(mSelector, op, attachment);
            mSocket.register(mHandshakeSelector, op, attachment);
            mSource = source;
            mSource.configureBlocking(false);
            mSource.register(mSelector, op, new SourceHandler());
            mSink = sink;

            SSLSession session = mEngine.getSession();
            int appBufSize = session.getApplicationBufferSize();
            int netBufSize = session.getPacketBufferSize();
            mMyAppData = ByteBuffer.allocate(0);
            mMyNetData = ByteBuffer.allocate(netBufSize);
            mPeerAppData = ByteBuffer.allocate(appBufSize);
            mPeerNetData = ByteBuffer.allocate(0);

            mEngine.beginHandshake();
        }

        public void run() {
            try {
                try {
                    mainloop();
                }
                finally {
                    mSink.close();
                }
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }

        private void closeSocket() throws IOException {
            if (mSource.isOpen()) {
                closeSource();
            }
            mSocket.keyFor(mSelector).cancel();
            mSocket.keyFor(mHandshakeSelector).cancel();
            mSocket.close();
        }

        private void closeSource() throws IOException {
            mEngine.closeOutbound();
            mSource.keyFor(mSelector).cancel();
            mSource.close();
        }

        private ByteBuffer enlargeBuffer(ByteBuffer buffer, int neededSize) {
            int position = buffer.position();
            ByteBuffer newBuffer = ByteBuffer.allocate(position + neededSize);
            buffer.flip();
            newBuffer.put(buffer);
            return newBuffer;
        }

        private void flush(ByteBuffer src,
                           WritableByteChannel dst) throws IOException {
            src.flip();
            while (src.hasRemaining()) {
                dst.write(src);
            }
            src.clear();
        }

        private void log(String message) {
            //System.out.println(message);
            mLogger.info(message);
        }

        private void log(String fmt, Object... args) {
            log(String.format(fmt, args));
        }

        private void log(String tag, SSLEngineResult result) {
            StringBuilder buffer = new StringBuilder();
            buffer.append(String.format("%s: ", tag));
            buffer.append(String.format("status=%s, ", result.getStatus()));
            buffer.append(String.format("handshakeStatus=%s, ",
                                        result.getHandshakeStatus()));
            buffer.append(String.format("bytesConsumed=%d, ",
                                        result.bytesConsumed()));
            buffer.append(String.format("bytesProduced=%d",
                                        result.bytesProduced()));
            log(buffer.toString());
        }

        private void logStatus() {
            log("mSelector.keys().size()=%d", mSelector.keys().size());
            log("mSocket.isOpen()=%s", mSocket.isOpen());
            log("mSource.isOpen()=%s", mSource.isOpen());
            HandshakeStatus hs = mEngine.getHandshakeStatus();
            log("mEngine.getHandshakeStatus()=%s", hs);
            log("mEngine.isOutboundDone()=%s", mEngine.isOutboundDone());
            log("mEngine.isInboundDone()=%s", mEngine.isInboundDone());
            log("mPeerNetData=%s", dumpBuffer(mPeerNetData));
            log("mMyAppData=%s", dumpBuffer(mMyAppData));
        }

        private String dumpBuffer(ByteBuffer buffer) {
            String fmt = "ByteBuffer(capacity=%d, limit=%d, position=%d, remaining=%d)";
            return String.format(fmt, buffer.capacity(), buffer.limit(),
                                 buffer.position(), buffer.remaining());
        }

        private void header(String title, String mark) {
            int width = 80;
            int len = title.length();
            int left = (width - (len + 2)) / 2;
            int right = left + len % 2;
            StringBuilder buffer = new StringBuilder();
            for (int i = 0; i < left; i++) {
                buffer.append(mark);
            }
            buffer.append(" ");
            buffer.append(title);
            buffer.append(" ");
            for (int i = 0; i < right; i++) {
                buffer.append(mark);
            }
            log(buffer.toString());
        }

        private void header(String title) {
            header(title, "*");
        }

        private void mainloop() throws IOException {
            while (mSocket.isOpen() || mPeerNetDataAvailable) {
                ToDo todo;
                SSLEngineResult.HandshakeStatus hs;
                hs = mEngine.getHandshakeStatus();
                //log("handshake status: %s", hs);
                switch (hs) {
                case NEED_TASK:
                    todo = ToDo.TASK;
                    break;
                case NEED_WRAP:
                    todo = mSocket.isOpen() ? ToDo.WRAP : ToDo.UNWRAP;
                    break;
                case NEED_UNWRAP:
                    todo = mPeerNetDataAvailable ? ToDo.UNWRAP : ToDo.SELECT;
                    break;
                case NOT_HANDSHAKING:
                    if (mPeerNetDataAvailable) {
                        todo = ToDo.UNWRAP;
                    }
                    else if (mMyAppData.hasRemaining()) {
                        todo = ToDo.WRAP;
                    }
                    else {
                        todo = ToDo.SELECT;
                    }
                    break;
                case FINISHED:
                default:
                    String fmt = "invalid handshake status: %s";
                    throw new Error(String.format(fmt, hs));
                }

                SSLEngineResult result;
                switch (todo) {
                case WRAP:
                    result = mEngine.wrap(mMyAppData, mMyNetData);
                    //log("wrap", result);
                    SSLEngineResult.Status status = result.getStatus();
                    switch (status) {
                    case BUFFER_OVERFLOW:
                        SSLSession session = mEngine.getSession();
                        int netBufSize = session.getPacketBufferSize();
                        mMyNetData = enlargeBuffer(mMyNetData, netBufSize);
                        break;
                    case BUFFER_UNDERFLOW:
                        throw new Error("BUFFER_UNDERFLOW for wrap");
                    case CLOSED:
                        closeSource();
                        // FALLTHROUGH
                    case OK:
                        flush(mMyNetData, mSocket);
                        break;
                    default:
                        String fmt = "invalid status: %s";
                        throw new Error(String.format(fmt, status));
                    }
                    break;
                case UNWRAP:
                    result = mEngine.unwrap(mPeerNetData, mPeerAppData);
                    //log("unwrap", result);
                    status = result.getStatus();
                    switch (status) {
                    case BUFFER_OVERFLOW:
                        SSLSession session = mEngine.getSession();
                        int appBufSize = session.getApplicationBufferSize();

                        /*
                         * When the master crashes, SSLEngine.unwrap() returns
                         * BUFFER_OVERFLOW even though the mPeerAppData has
                         * enough space. I do not know why.
                         *
                         * In this case, this loop never ended. I throw an Error
                         * to stop.
                         */
                        if (appBufSize <= mPeerAppData.remaining()) {
                            String message = "SSLEngine.unwrap() RETURNS UNEXPECTED BUFFER_OVERFLOW";
                            mLogger.err("%s: mPeerNetData=%s, mPeerAppData=%s, appBufSize=%d",
                                        message, dumpBuffer(mPeerNetData),
                                        dumpBuffer(mPeerAppData), appBufSize);
                            logStatus();
                            throw new Error(message);
                        }

                        mPeerAppData = enlargeBuffer(mPeerAppData, appBufSize);
                        break;
                    case BUFFER_UNDERFLOW:
                        mPeerNetDataAvailable = false;
                        break;
                    case CLOSED:
                        closeSocket();
                        mPeerNetDataAvailable = false;
                        // FALLTHROUGH
                    case OK:
                        flush(mPeerAppData, mSink);
                        mPeerNetDataAvailable = mPeerNetData.hasRemaining();
                        break;
                    default:
                        String fmt = "invalid status: %s";
                        throw new Error(String.format(fmt, status));
                    }
                    break;
                case TASK:
                    Runnable task;
                    while ((task = mEngine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    break;
                case SELECT:
                    Selector selector;
                    selector = hs == HandshakeStatus.NOT_HANDSHAKING
                            ? mSelector
                            : mHandshakeSelector;
                    selector.select(120 * 1000);    // [msec]
                    Set<SelectionKey> keys = selector.selectedKeys();
                    int nKeys = keys.size();
                    switch (nKeys) {
                    case 0:
                        throw new IOException("timeout");
                    case 1:
                    case 2:
                        break;
                    default:
                        String fmt = "invalid key number: %d";
                        throw new Error(String.format(fmt, nKeys));
                    }
                    for (SelectionKey key: keys) {
                        Object attachment = key.attachment();
                        ChannelHandler handler = (ChannelHandler)attachment;
                        handler.handle();
                    }
                    keys.clear();
                    break;
                default:
                    throw new Error(String.format("invalid ToDo: %s", todo));
                }

                //logStatus();
            }
        }
    }

    private static Logging.Logger mLogger;

    private Thread mThread;
    private Worker mWorker;

    public SSLFrontEnd(SSLContext context, SocketChannel socket,
                       Pipe.SourceChannel source,
                       Pipe.SinkChannel sink) throws IOException {
        mWorker = new Worker(context, socket, source, sink);
        mThread = new Thread(mWorker);
        mThread.start();
    }

    public void join() throws InterruptedException {
        mThread.join();
    }

    private static int testOpenSSL() {
        SocketAddress address = new InetSocketAddress("127.0.0.1", 50000);
        SocketChannel socket;
        Pipe front2back;
        Pipe back2front;
        try {
            socket = SocketChannel.open(address);
            front2back = Pipe.open();
            back2front = Pipe.open();
        }
        catch (IOException e) {
            e.printStackTrace();
            return 1;
        }

        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 2;
        }
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("JKS");
        }
        catch (KeyStoreException e) {
            e.printStackTrace();
            return 3;
        }
        char[] password = "hogehoge".toCharArray();
        try {
            keyStore.load(new FileInputStream("tests/ssl/keystore"), password);
        }
        catch (IOException e) {
            e.printStackTrace();
            return 4;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 5;
        }
        catch (CertificateException e) {
            e.printStackTrace();
            return 6;
        }
        TrustManagerFactory factory;
        try {
            factory = TrustManagerFactory.getInstance("SunX509");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 7;
        }
        try {
            factory.init(keyStore);
        }
        catch (KeyStoreException e) {
            e.printStackTrace();
            return 8;
        }
        TrustManager[] tm = factory.getTrustManagers();
        try {
            context.init(null, tm, null);
        }
        catch (KeyManagementException e) {
            e.printStackTrace();
            return 9;
        }
        SSLFrontEnd testee;
        try {
            testee = new SSLFrontEnd(context, socket, back2front.source(),
                                     front2back.sink());
        }
        catch (IOException e) {
            e.printStackTrace();
            return 10;
        }
        Pipe.SinkChannel sink = back2front.sink();
        ByteBuffer buffer = ByteBuffer.allocate(256);
        buffer.put("HELLO\r\n".getBytes());
        buffer.flip();
        try {
            sink.write(buffer);
            sink.close();
        }
        catch (IOException e) {
            e.printStackTrace();
            return 11;
        }
        try {
            testee.join();
        }
        catch (InterruptedException e) {
            e.printStackTrace();
            return 12;
        }

        return 0;
    }

    private static int testHttps(String path) {
        String host = "127.0.0.1";
        SocketAddress address = new InetSocketAddress(host, 50443);
        SocketChannel socket;
        Pipe front2back;
        Pipe back2front;
        try {
            socket = SocketChannel.open(address);
            front2back = Pipe.open();
            back2front = Pipe.open();
        }
        catch (IOException e) {
            e.printStackTrace();
            return 1;
        }

        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 2;
        }
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("JKS");
        }
        catch (KeyStoreException e) {
            e.printStackTrace();
            return 3;
        }
        char[] password = "hogehoge".toCharArray();
        try {
            keyStore.load(new FileInputStream("tests/ssl/keystore"), password);
        }
        catch (IOException e) {
            e.printStackTrace();
            return 4;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 5;
        }
        catch (CertificateException e) {
            e.printStackTrace();
            return 6;
        }
        TrustManagerFactory factory;
        try {
            factory = TrustManagerFactory.getInstance("SunX509");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 7;
        }
        try {
            factory.init(keyStore);
        }
        catch (KeyStoreException e) {
            e.printStackTrace();
            return 8;
        }
        TrustManager[] tm = factory.getTrustManagers();
        try {
            context.init(null, tm, null);
        }
        catch (KeyManagementException e) {
            e.printStackTrace();
            return 9;
        }
        SSLFrontEnd testee;
        try {
            testee = new SSLFrontEnd(context, socket, back2front.source(),
                                     front2back.sink());
        }
        catch (IOException e) {
            e.printStackTrace();
            return 10;
        }
        Pipe.SinkChannel sink = back2front.sink();
        ByteBuffer buffer = ByteBuffer.allocate(256);
        String s = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n";
        buffer.put(String.format(s, path, host).getBytes());
        buffer.flip();
        try {
            sink.write(buffer);
            sink.close();

            OutputStream out = new FileOutputStream("https.log");
            try {
                Pipe.SourceChannel source = front2back.source();
                ByteBuffer buf = ByteBuffer.allocate(8192);
                while (source.read(buf) != -1) {
                    buf.flip();
                    byte[] a = new byte[buf.remaining()];
                    buf.get(a);
                    out.write(a);
                    buf.clear();
                }
            }
            finally {
                out.close();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
            return 11;
        }
        try {
            testee.join();
        }
        catch (InterruptedException e) {
            e.printStackTrace();
            return 12;
        }

        return 0;
    }

    private static int testSSLTestd() {
        SocketAddress address = new InetSocketAddress("127.0.0.1", 50001);
        SocketChannel socket;
        Pipe front2back;
        Pipe back2front;
        try {
            socket = SocketChannel.open(address);
            front2back = Pipe.open();
            back2front = Pipe.open();
        }
        catch (IOException e) {
            e.printStackTrace();
            return 1;
        }

        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 2;
        }
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("JKS");
        }
        catch (KeyStoreException e) {
            e.printStackTrace();
            return 3;
        }
        char[] password = "hogehoge".toCharArray();
        try {
            keyStore.load(new FileInputStream("tests/ssl/keystore"), password);
        }
        catch (IOException e) {
            e.printStackTrace();
            return 4;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 5;
        }
        catch (CertificateException e) {
            e.printStackTrace();
            return 6;
        }
        TrustManagerFactory factory;
        try {
            factory = TrustManagerFactory.getInstance("SunX509");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return 7;
        }
        try {
            factory.init(keyStore);
        }
        catch (KeyStoreException e) {
            e.printStackTrace();
            return 8;
        }
        TrustManager[] tm = factory.getTrustManagers();
        try {
            context.init(null, tm, null);
        }
        catch (KeyManagementException e) {
            e.printStackTrace();
            return 9;
        }
        SSLFrontEnd testee;
        try {
            testee = new SSLFrontEnd(context, socket, back2front.source(),
                                     front2back.sink());
        }
        catch (IOException e) {
            e.printStackTrace();
            return 10;
        }
        Pipe.SinkChannel sink = back2front.sink();
        try {
            try {
                InputStream in = new FileInputStream("random.dat");
                try {
                    int bufsize = 8192;
                    byte[] a = new byte[bufsize];
                    ByteBuffer b = ByteBuffer.allocate(bufsize);
                    /*
                    Random random = new Random(0);
                    int nBytes;
                    while ((nBytes = in.read(a, 0,
                                             random.nextInt(bufsize))) != -1) {
                        b.put(a, 0, nBytes);
                        b.flip();
                        while (b.hasRemaining()) {
                            sink.write(b);
                        }
                        b.clear();
                    }
                    */
                    int nBytes = 0;
                    while (nBytes < 1024 * 1024) {
                        int n = in.read(a);
                        if (n == -1) {
                            throw new IOException("unexpected EOF");
                        }

                        b.put(a, 0, n);
                        b.flip();
                        while (b.hasRemaining()) {
                            sink.write(b);
                        }
                        b.clear();

                        nBytes += n;
                    }
                }
                finally {
                    in.close();
                }

                String dst = "SSLFrontEnd.dat";
                new File(dst).delete();
                OutputStream out = new FileOutputStream(dst);
                try {
                    Pipe.SourceChannel source = front2back.source();
                    ByteBuffer buf = ByteBuffer.allocate(8192);
                    while (source.read(buf) != -1) {
                        buf.flip();
                        while (buf.hasRemaining()) {
                            int len = buf.remaining();
                            byte[] a = new byte[len];
                            buf.get(a);
                            out.write(a, 0, len);
                        }
                        buf.clear();
                    }
                }
                finally {
                    out.close();
                }
            }
            finally {
                sink.close();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
            return 11;
        }
        try {
            testee.join();
        }
        catch (InterruptedException e) {
            e.printStackTrace();
            return 12;
        }

        return 0;
    }

    public static void main(String[] args) {
        List<String> sa = new LinkedList<String>();
        for (int i = 0; i < args.length; i++) {
            sa.add(args[i]);
        }

        while ((0 < sa.size()) && sa.get(0).startsWith("--")) {
            String a = sa.remove(0);
            if (a.equals("--debug")) {
                System.setProperty("javax.net.debug", "all");
            }
        }

        String type = sa.size() == 0 ? null : sa.remove(0);
        int status;
        if (type == null) {
            status = testSSLTestd();
        }
        else if (type.equals("https")) {
            String path = sa.size() == 0 ? "/" : sa.remove(0);
            status = testHttps(path);
        }
        else if (type.equals("openssl")) {
            status = testOpenSSL();
        }
        else {
            throw new Error(String.format("unknown type: %s", type));
        }

        System.exit(status);
    }

    static {
        mLogger = new Logging.Logger("SSLFrontEnd");
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
