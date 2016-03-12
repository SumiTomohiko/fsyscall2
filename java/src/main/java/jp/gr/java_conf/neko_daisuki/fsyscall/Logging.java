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

        private interface LoggingProc {

            public void log(String fmt, Object... args);
        }

        private class VerboseProc implements LoggingProc {

            public void log(String fmt, Object... args) {
                verbose(fmt, args);
            }
        }

        private class ErrProc implements LoggingProc {

            public void log(String fmt, Object... args) {
                err(fmt, args);
            }
        }

        private final LoggingProc VERBOSE_PROC = new VerboseProc();
        private final LoggingProc ERR_PROC = new ErrProc();

        private String mTag;

        public Logger(String tag) {
            mTag = tag;
        }

        public void verbose(String fmt, Object... args) {
            mDestination.verbose(formatMessage(fmt, args));
        }

        public void verbose(Throwable e, String fmt, Object... args) {
            log(VERBOSE_PROC, e, fmt, args);
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
            log(ERR_PROC, e, fmt, args);
        }

        public void trace(String fmt, Object... args) {
            verbose("%s: %s", getCallerPosition(), String.format(fmt, args));
        }

        public void trace() {
            verbose("%s", getCallerPosition());
        }

        public void stacktrace(String fmt, Object... args) {
            verbose(fmt, args);
            logStacktrace(VERBOSE_PROC, new Throwable().getStackTrace());
        }

        private String getCallerPosition() {
            StackTraceElement[] stack = new Throwable().getStackTrace();
            return 0 < stack.length ? stack[2].toString() : "unknown";
        }

        private String formatMessage(String fmt, Object[] args) {
            String name = Thread.currentThread().getName();
            String message = String.format(fmt, args);
            return String.format("%s: %s: %s", name, mTag, message);
        }

        private void log(LoggingProc proc, Throwable e, String fmt,
                         Object... args) {
            proc.log("%s: %s", String.format(fmt, args), e.getMessage());
            logStacktrace(proc, e.getStackTrace());
        }

        private void logStacktrace(LoggingProc proc,
                                   StackTraceElement[] elements) {
            int len = elements.length;
            for (int i = 0; i < len; i++) {
                proc.log(elements[i].toString());
            }
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
