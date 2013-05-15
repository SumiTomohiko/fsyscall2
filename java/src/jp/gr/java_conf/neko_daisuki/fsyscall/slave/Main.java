package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;

public class Main {

    private static class Pipe {

        private PipedInputStream mIn;
        private PipedOutputStream mOut;

        public Pipe() throws IOException {
            mIn = new PipedInputStream();
            mOut = new PipedOutputStream(mIn);
        }

        public InputStream getInput() {
            return mIn;
        }

        public OutputStream getOutput() {
            return mOut;
        }
    }

    public void run(InputStream in, OutputStream out) throws IOException {
        Pipe slave2hub = new Pipe();
        Pipe hub2slave = new Pipe();
        Slave slave = new Slave(hub2slave.getInput(), slave2hub.getOutput());
        SlaveHub slaveHub = new SlaveHub(
                in, out,
                slave2hub.getInput(), hub2slave.getOutput());
    }

    private static void usage(PrintStream out) {
        out.println("usage: Main rfd wfd");
    }

    /**
     * This is the tester method. This class requires two parameters -- the file
     * descriptor to read and another one to write. But, Java DOES NOT HAVE ANY
     * WAYS to make InputStream/OutputStream from file descriptor number. So
     * this method opens <code>/dev/fd/<var>rfd</var></code> and
     * <code>/dev/fd/<var>wfd</var></code> to make streams. This way is
     * available on FreeBSD 9.1 with fdescfs mounted on <code>/dev/fd</code>. I
     * do not know if the same way is usable on other platforms.
     */
    public static void main(String[] args) {
        int rfd, wfd;
        try {
            rfd = Integer.parseInt(args[0]);
            wfd = Integer.parseInt(args[1]);
        }
        catch (ArrayIndexOutOfBoundsException _) {
            Main.usage(System.out);
            return;
        }
        catch (NumberFormatException _) {
            Main.usage(System.out);
            return;
        }
        String fmt = "/dev/fd/%d";
        String inPath = String.format(fmt, new Integer(rfd));
        String outPath = String.format(fmt, new Integer(wfd));
        InputStream in;
        OutputStream out;
        try {
            in = new FileInputStream(inPath);
            out = new FileOutputStream(outPath);
        }
        catch (IOException e) {
            e.printStackTrace();
            return;
        }

        try {
            new Main().run(in, out);
        }
        catch (Throwable e) {
            e.printStackTrace();
        }
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
