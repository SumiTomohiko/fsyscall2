package jp.gr.java_conf.neko_daisuki.fsyscall;

/**
 * Logging class. The name of this class must be Logger or Log, but both of them
 * are used (java.util.logging.Logger and android.util.Log). I can use them with
 * this class in prepending package name, but I dislike to write long name (Java
 * must have the function to rename a class in importer file such as
 * &quot;as&quot; keyword in Python). I had one candidate of this name --
 * LoggerWrapper, but it is also long, so it is hard to use. Finally I decided
 * to use very simple name, L. I do not think that this is the best.
 */
public class L {

    public interface Handler {

        public void verbose(String message);
        public void debug(String message);
        public void info(String message);
        public void warn(String message);
        public void err(String message);
    }

    private static class FakeHandler implements Handler {

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

    private static Handler mHandler;

    public static void verbose(String message) {
        mHandler.verbose(message);
    }

    public static void debug(String message) {
        mHandler.debug(message);
    }

    public static void info(String message) {
        mHandler.info(message);
    }

    public static void warn(String message) {
        mHandler.warn(message);
    }

    public static void err(String message) {
        mHandler.err(message);
    }

    public static void setHandler(Handler handler) {
        mHandler = handler;
    }

    /**
     * The constructor to disable <code>new</code> operator.
     */
    private L() {
    }

    static {
        setHandler(new FakeHandler());
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
