package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.util.StringUtil;

public class Links {

    public static class NotAbsolutePathException extends Exception {

        public NotAbsolutePathException(String type, String path) {
            super(String.format("%s must be absolute: %s", type, path));
        }
    }

    public class DuplicateSettingsException extends Exception {
    }

    private interface Node {

        public String traverse(List<String> elems);
        public void put(String dest, List<String> elems);
    }

    private static class InnerNode implements Node {

        private Map<String, Node> mNodes = new HashMap<String, Node>();

        @Override
        public String traverse(List<String> elems) {
            int size = elems.size();
            if (size == 0) {
                return null;
            }
            Node node = mNodes.get(elems.get(0));
            if (node == null) {
                return null;
            }
            return node.traverse(elems.subList(1, size));
        }

        @Override
        public void put(String dest, List<String> elems) {
            int size = elems.size();
            if (size == 0) {
                return;
            }
            String name = elems.get(0);
            if (size == 1) {
                mNodes.put(name, new Leaf(dest));
                return;
            }
            InnerNode node = new InnerNode();
            node.put(dest, elems.subList(1, size));
            mNodes.put(name, node);
        }
    }

    private static class Leaf implements Node {

        private String mDestination;

        public Leaf(String destination) {
            mDestination = destination;
        }

        @Override
        public String traverse(List<String> elems) {
            StringBuilder buf = new StringBuilder(mDestination);
            int size = elems.size();
            for (int i = 0; i < size; i++) {
                buf.append(SEPARATOR);
                buf.append(elems.get(i));
            }
            return buf.toString();
        }

        @Override
        public void put(String dest, List<String> elems) {
            // nothing
        }
    }

    private static final String ROOT_DIR = "/";
    private static final String SEPARATOR = "/";

    private Node mRootNode = new InnerNode();

    public void put(String dest, String src) throws NotAbsolutePathException {
        if (!dest.startsWith(ROOT_DIR)) {
            throw new NotAbsolutePathException("destination path", dest);
        }
        if (!src.startsWith(ROOT_DIR)) {
            throw new NotAbsolutePathException("source path", src);
        }
        mRootNode.put(dest, listPathElements(src));
    }

    public String get(String path) throws NotAbsolutePathException {
        if (!path.startsWith(ROOT_DIR)) {
            throw new NotAbsolutePathException("path", path);
        }
        String dest = mRootNode.traverse(listPathElements(path));
        return dest != null ? dest : path;
    }

    private List<String> listPathElements(String path) {
        List<String> l = new LinkedList<String>();
        String[] sa = path.split(SEPARATOR);
        int len = sa.length;
        for (int i = 1; i < len; i++) {
            l.add(sa[i]);
        }
        return l;
    }

    private static void test(String dest, String src, String path,
                             String expected) {
        String result;
        String actual;
        Links links = new Links();
        try {
            links.put(dest, src);
            actual = links.get(path);
            result = expected.equals(actual) ? "OK"
                                             : String.format("NG (%s)", actual);
        }
        catch (NotAbsolutePathException unused) {
            result = "ERROR";
        }
        String fmt = "dest=%s, src=%s, path=%s, expected=%s: %s";
        String msg = String.format(fmt, StringUtil.quote(dest),
                                   StringUtil.quote(src),
                                   StringUtil.quote(path),
                                   StringUtil.quote(expected), result);
        System.out.println(msg);
    }

    public static void main(String[] args) {
        test("/sdcard", "/home/fsyscall", "/home/fsyscall/dbus",
             "/sdcard/dbus");
        test("/sdcard", "/home/fsyscall", "/tmp", "/tmp");
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
