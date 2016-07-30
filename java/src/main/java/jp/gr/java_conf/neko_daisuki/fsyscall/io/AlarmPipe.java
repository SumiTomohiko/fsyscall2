package jp.gr.java_conf.neko_daisuki.fsyscall.io;

import java.io.IOException;
import java.io.OutputStream;

import jp.gr.java_conf.neko_daisuki.fsyscall.slave.Alarm;

public class AlarmPipe extends Pipe {

    private class AlarmPipeOutputStream extends PipeOutputStream {

        private Alarm mAlarm;

        public AlarmPipeOutputStream(Alarm alarm) {
            mAlarm = alarm;
        }

        @Override
        public void write(int b) throws IOException {
            super.write(b);
            mAlarm.alarm();
        }
    }

    private Alarm mAlarm;

    public AlarmPipe(Alarm alarm) throws IOException {
        mAlarm = alarm;
    }

    @Override
    protected OutputStream buildOutputStream() {
        return new AlarmPipeOutputStream(mAlarm);
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4