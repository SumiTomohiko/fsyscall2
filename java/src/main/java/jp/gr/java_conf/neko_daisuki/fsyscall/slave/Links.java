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

    private static class Node {

        private NormalizedPath mDestination;
        private Map<String, Node> mNodes = new HashMap<String, Node>();

        public NormalizedPath walk(List<String> elems) throws NormalizedPath.InvalidPathException {
            return walk0(new NormalizedPath("/"), new LinkedList<String>(),
                         elems);
        }

        public void put(NormalizedPath dest, List<String> elems) {
            int size = elems.size();
            if (size == 0) {
                mDestination = dest;
                return;
            }

            String name = elems.get(0);
            List<String> rest = elems.subList(1, size);
            Node node = mNodes.get(name);
            if (node != null) {
                node.put(dest, rest);
                return;
            }

            Node newNode = new Node();
            newNode.put(dest, rest);
            mNodes.put(name, newNode);
        }

        private NormalizedPath walk0(NormalizedPath path, List<String> accum,
                                     List<String> elems) throws NormalizedPath.InvalidPathException {
            if (mDestination != null) {
                int size = elems.size();
                if (size == 0) {
                    return mDestination;
                }
                String name = elems.get(0);
                Node node = mNodes.get(name);
                if (node == null) {
                    return new NormalizedPath(mDestination, chain(elems));
                }
                List<String> newAccum = new LinkedList<String>();
                newAccum.add(name);
                List<String> rest = elems.subList(1, size);
                return node.walk0(mDestination, newAccum, rest);
            }

            int size = elems.size();
            if (size == 0) {
                return new NormalizedPath(path, chain(accum));
            }
            String name = elems.get(0);
            accum.add(name);
            List<String> rest = elems.subList(1, size);
            Node node = mNodes.get(name);
            if (node == null) {
                List<String> l = new LinkedList<String>();
                l.addAll(accum);
                l.addAll(rest);
                return new NormalizedPath(path, chain(l));
            }
            return node.walk0(path, accum, rest);
        }

        private String chain(List<String> elems) {
            StringBuilder buffer = new StringBuilder();
            String sep = "";
            for (String s: elems) {
                buffer.append(sep);
                buffer.append(s);
                sep = SEPARATOR;
            }
            return buffer.toString();
        }
    }

    private static final String SEPARATOR = "/";

    private Node mRootNode = new Node();

    public void put(NormalizedPath dest, NormalizedPath src) {
        mRootNode.put(dest, listPathElements(src));
    }

    public NormalizedPath get(NormalizedPath path) {
        try {
            return mRootNode.walk(listPathElements(path));
        }
        catch (NormalizedPath.InvalidPathException e) {
            String message = String.format("unexpected exception for %s", path);
            throw new Error(message, e);
        }
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

    private static void test(String tag, Links links, NormalizedPath path,
                             NormalizedPath expected) {
        NormalizedPath actual = links.get(path);
        String result = expected.equals(actual) ? "OK"
                                                : String.format("NG (%s)",
                                                                actual);
        String fmt = "%s: path=%s, expected=%s: %s";
        String msg = String.format(fmt, tag, StringUtil.quote(path.toString()),
                                   StringUtil.quote(expected.toString()),
                                   result);
        System.out.println(msg);
    }

    private static void test(String tag, Links links, String path,
                             String expected) {
        try {
            test(tag, links, new NormalizedPath(path),
                 new NormalizedPath(expected));
        }
        catch (NormalizedPath.InvalidPathException e) {
            e.printStackTrace();
        }
    }

    private static void test(NormalizedPath dest, NormalizedPath src,
                             NormalizedPath path, NormalizedPath expected) {
        String tag = String.format("test(dest=%s, src=%s)",
                                   StringUtil.quote(dest.toString()),
                                   StringUtil.quote(src.toString()));
        Links links = new Links();
        links.put(dest, src);
        test(tag, links, path, expected);
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

    private static void test2(NormalizedPath path, NormalizedPath expected)
                              throws NormalizedPath.InvalidPathException {
        Links links = new Links();
        links.put(new NormalizedPath("/foobar"), new NormalizedPath("/"));
        links.put(new NormalizedPath("/foobar/buzquux"),
                  new NormalizedPath("/home"));
        test("test2", links, path, expected);
    }

    private static void test2(String path, String expected) {
        try {
            test2(new NormalizedPath(path), new NormalizedPath(expected));
        }
        catch (NormalizedPath.InvalidPathException e) {
            e.printStackTrace();
        }
    }

    private static void test3() {
        Links links = new Links();
        try {
            links.put(new NormalizedPath("/foobar"), new NormalizedPath("/"));
            links.put(new NormalizedPath("/foobar/usr/home"),
                      new NormalizedPath("/home"));
            links.put(new NormalizedPath("/foobar/usr/home/fsyscall/sdcard"),
                      new NormalizedPath("/home/fsyscall/sdcard"));
            test("test3", links, "/home/fsyscall/.local/share/fonts",
                 "/foobar/usr/home/fsyscall/.local/share/fonts");
        }
        catch (NormalizedPath.InvalidPathException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        test("/sdcard", "/home/fsyscall", "/home/fsyscall/dbus",
             "/sdcard/dbus");
        test("/sdcard", "/home/fsyscall", "/tmp", "/tmp");
        test("/foobar", "/", "/", "/foobar");
        test("/foobar", "/", "/hogehoge", "/foobar/hogehoge");
        test2("/", "/foobar");
        test2("/home", "/foobar/buzquux");
        test2("/home/hogehoge", "/foobar/buzquux/hogehoge");
        test2("/etc", "/foobar/etc");
        test3();
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
