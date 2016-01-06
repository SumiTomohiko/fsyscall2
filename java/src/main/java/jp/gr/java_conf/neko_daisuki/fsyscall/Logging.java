package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Logging {

    public interface Destination {

        public void verbose(String message);
        public void debug(String message);
        public void info(String message);
        public void warn(String message);
        public void err(String message);
    }

    private static class NullDestination implements Destination {

        public void verbose(String message) {
        }

        public void debug(String message) {
        }

        public void info(String message) {
        }

        public void warn(String message) {
        }

        public void err(String message) {
        }
    }

    public static class FileDestination implements Destination {

        private PrintWriter mWriter;
        private DateFormat mDateFormatter;

        public FileDestination(String path) throws IOException {
            Writer out = new BufferedWriter(new FileWriter(path, true));
            mWriter = new PrintWriter(out, true);
            mDateFormatter = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        }

        public void verbose(String message) {
            mWriter.println(formatMessage("VERB", message));
        }

        public void debug(String message) {
            mWriter.println(formatMessage("DEBUG", message));
        }

        public void info(String message) {
            mWriter.println(formatMessage("INFO", message));
        }

        public void warn(String message) {
            mWriter.println(formatMessage("WARN", message));
        }

        public void err(String message) {
            mWriter.println(formatMessage("ERR", message));
        }

        private String formatMessage(String level, String message) {
            String timestamp = mDateFormatter.format(new Date());
            String name = Thread.currentThread().getName();
            String fmt = "[%s] %s: %s: %s";
            return String.format(fmt, timestamp, name, level, message);
        }
    }

    public static class Logger {

        private String mTag;

        public Logger(String tag) {
            mTag = tag;
        }

        public void verbose(String fmt, Object... args) {
            mDestination.verbose(formatMessage(fmt, args));
        }

        public void debug(String fmt, Object... args) {
            mDestination.debug(formatMessage(fmt, args));
        }

        public void info(String fmt, Object... args) {
            mDestination.info(formatMessage(fmt, args));
        }

        public void warn(String fmt, Object... args) {
            mDestination.warn(formatMessage(fmt, args));
        }

        public void err(String fmt, Object... args) {
            mDestination.err(formatMessage(fmt, args));
        }

        public void err(Throwable e, String fmt, Object... args) {
            String message = String.format(fmt, args);
            err(String.format("%s: %s", message, e.getMessage()));
            StackTraceElement[] elements = e.getStackTrace();
            for (int i = 0; i < elements.length; i++) {
                err(elements[i].toString());
            }
        }

        public void trace(String tag) {
            StackTraceElement[] stack = new Throwable().getStackTrace();
            String message = 0 < stack.length ? stack[1].toString() : "unknown";
            verbose("%s: %s", tag, message);
        }

        private String formatMessage(String fmt, Object[] args) {
            String name = Thread.currentThread().getName();
            String message = String.format(fmt, args);
            return String.format("%s: %s: %s", name, mTag, message);
        }
    }

    private static Destination mDestination;

    public static void setDestination(Destination destination) {
        mDestination = destination;
    }

    private Logging() {
    }

    static {
        setDestination(new NullDestination());
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
