package jp.gr.java_conf.neko_daisuki.fsyscall.slave;

class Alarm {

    public void alarm() {
        synchronized (this) {
            notifyAll();
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
