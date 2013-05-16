package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.util.HashMap;
import java.util.Map;

public class CommandDispatcher {

    public abstract static class Proc {

        public abstract void call(Command command);
    }

    private Map<Command, Proc> mTable;

    public CommandDispatcher() {
        mTable = new HashMap<Command, Proc>();
    }

    public void dispatch(Command command) {
        mTable.get(command).call(command);
    }

    public void addEntry(Command command, Proc proc) {
        mTable.put(command, proc);
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
