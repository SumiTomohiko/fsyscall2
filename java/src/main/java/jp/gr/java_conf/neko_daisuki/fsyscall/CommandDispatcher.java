package jp.gr.java_conf.neko_daisuki.fsyscall;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class CommandDispatcher {

    public abstract static class Proc implements Unix.Constants {

        public abstract void call(Command command) throws IOException,
                                                          SigkillException;
    }

    private Map<Command, Proc> mTable;

    public CommandDispatcher() {
        mTable = new HashMap<Command, Proc>();
    }

    public Proc get(Command command) {
        return mTable.get(command);
    }

    public Set<Command> commandSet() {
        return mTable.keySet();
    }

    public void addEntry(Command command, Proc proc) {
        mTable.put(command, proc);
    }
}

/**
 * vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
 */
