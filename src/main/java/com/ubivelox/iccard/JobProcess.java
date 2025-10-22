package com.ubivelox.iccard;

import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.pkcs.IaikPKCSWrapper;
import com.ubivelox.iccard.task.HmcContext;
import com.ubivelox.iccard.task.SubTask;
import com.ubivelox.iccard.task.a1.A1Protocol;
import com.ubivelox.iccard.task.a1.A1Task;
import com.ubivelox.iccard.task.a2.A2Protocol;
import com.ubivelox.iccard.task.a2.A2Task;
import com.ubivelox.iccard.task.b1.B1Protocol;
import com.ubivelox.iccard.task.b1.B1Task;
import com.ubivelox.iccard.task.b2.B2Protocol;
import com.ubivelox.iccard.task.b2.B2Task;
import com.ubivelox.iccard.task.b3.B3Protocol;
import com.ubivelox.iccard.task.b3.B3Task;
import com.ubivelox.iccard.task.b4.B4Protocol;
import com.ubivelox.iccard.task.b4.B4Task;
import com.ubivelox.iccard.task.b5.B5Protocol;
import com.ubivelox.iccard.task.b5.B5Task;
import com.ubivelox.iccard.task.c0.C0Protocol;
import com.ubivelox.iccard.task.c0.C0Task;
import com.ubivelox.iccard.task.c1.C1Protocol;
import com.ubivelox.iccard.task.c1.C1Task;
import com.ubivelox.iccard.util.PropertyReader;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
@NoArgsConstructor
public class JobProcess {
    protected static IaikPKCSWrapper pkcs11Wrapper = new IaikPKCSWrapper();
    protected String charset = PropertyReader.getProperty("character.encoding");

    public Long initLibrary() {
        SubTask subTask = new SubTask();
        String test = subTask.initModule();
        if (StringUtils.equals(Constants.YES, test)) {
            return 1L;
        } else {
            return -1L;
        }
    }

    public Long finalLibrary() {
        SubTask subTask = new SubTask();
        String test = subTask.finalModule();
        if (StringUtils.equals(Constants.YES, test)) {
            return 1L;
        } else {
            return -1L;
        }
    }

    public String processA1(String request) {
        A1Task task = new A1Task();
        HmcContext hyundaiContext = new HmcContext(task, A1Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processA2(String request) {
        A2Task task = new A2Task();
        HmcContext hyundaiContext = new HmcContext(task, A2Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processB1(String request) {
        B1Task task = new B1Task();
        HmcContext hyundaiContext = new HmcContext(task, B1Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processB2(String request) {
        B2Task task = new B2Task();
        HmcContext hyundaiContext = new HmcContext(task, B2Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processB3(String request) {
        B3Task task = new B3Task();
        HmcContext hyundaiContext = new HmcContext(task, B3Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processB4(String request) {
        B4Task task = new B4Task();
        HmcContext hyundaiContext = new HmcContext(task, B4Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processB5(String request) {
        B5Task task = new B5Task();
        HmcContext hyundaiContext = new HmcContext(task, B5Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processC0(String request) {
        C0Task task = new C0Task();
        HmcContext hyundaiContext = new HmcContext(task, C0Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processC1(String request) {
        C1Task task = new C1Task();
        HmcContext hyundaiContext = new HmcContext(task, C1Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }
}
