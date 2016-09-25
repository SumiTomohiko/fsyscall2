package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import jp.gr.java_conf.neko_daisuki.fsyscall.util.NormalizedPath;
import jp.gr.java_conf.neko_daisuki.fsyscall.util.StringUtil;

public class Links {

    public class DuplicateSettingsException extends Exception {
    }

    private interface Node {

        public NormalizedPath traverse(List<String> elems);
        public void put(NormalizedPath dest, List<String> elems);
    }

    private static class InnerNode implements Node {

        private Map<String, Node> mNodes = new HashMap<String, Node>();

        @Override
        public NormalizedPath traverse(List<String> elems) {
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
        public void put(NormalizedPath dest, List<String> elems) {
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

        private NormalizedPath mDestination;

        public Leaf(NormalizedPath destination) {
            mDestination = destination;
        }

        @Override
        public NormalizedPath traverse(List<String> elems) {
            int size = elems.size();
            StringBuilder buf = new StringBuilder(size == 0 ? ""
                                                            : elems.get(0));
            for (int i = 1; i < size; i++) {
                buf.append(SEPARATOR);
                buf.append(elems.get(i));
            }
            return new NormalizedPath(mDestination, buf.toString());
        }

        @Override
        public void put(NormalizedPath dest, List<String> elems) {
            // nothing
        }
    }

    private static final String SEPARATOR = "/";

    private Node mRootNode = new InnerNode();

    public void put(NormalizedPath dest, NormalizedPath src) {
        mRootNode.put(dest, listPathElements(src));
    }

    public NormalizedPath get(NormalizedPath path) {
        NormalizedPath dest = mRootNode.traverse(listPathElements(path));
        return dest != null ? dest : path;
    }

    private List<String> listPathElements(NormalizedPath path) {
        List<String> l = new LinkedList<String>();
        String[] sa = path.toString().split(SEPARATOR);
        int len = sa.length;
        for (int i = 1; i < len; i++) {
            l.add(sa[i]);
        }
        return l;
    }

    private static void test(NormalizedPath dest, NormalizedPath src,
                             NormalizedPath path, NormalizedPath expected) {
        Links links = new Links();
        links.put(dest, src);
        NormalizedPath actual = links.get(path);
        String result = expected.equals(actual) ? "OK"
                                                : String.format("NG (%s)",
                                                                actual);
        String fmt = "dest=%s, src=%s, path=%s, expected=%s: %s";
        String msg = String.format(fmt, StringUtil.quote(dest.toString()),
                                   StringUtil.quote(src.toString()),
                                   StringUtil.quote(path.toString()),
                                   StringUtil.quote(expected.toString()),
                                   result);
        System.out.println(msg);
    }

    private static void test(String dest, String src, String path,
                             String expected) {
        try {
            test(new NormalizedPath(dest), new NormalizedPath(src),
                 new NormalizedPath(path), new NormalizedPath(expected));
        }
        catch (NormalizedPath.InvalidPathException e) {
            e.printStackTrace();
        }
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
