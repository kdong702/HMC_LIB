package com.ubivelox.iccard;

import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.LogbackFallbackInitializer;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.exception.ErrorCode;
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

import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@NoArgsConstructor
public class JobProcess {

    private static final JobProcess INSTANCE = new JobProcess();
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    protected String charset = PropertyReader.getProperty("character.encoding");

    public static JobProcess getInstance() {
        if (INSTANCE.initialized.compareAndSet(false, true)) {
            INSTANCE.initLibrary();
        }
        return INSTANCE;
    }

    public void initLibrary() {
        try {
            log.info("===== JobProcess initLibrary =====");
            LogbackFallbackInitializer.init();
            SubTask subTask = new SubTask();
            subTask.initModule();
        } catch (Exception e) {
            throw new CasException(ErrorCode.ERR_HSM_INIT);
        }

    }

    public void finalLibrary() {
        try {
            SubTask subTask = new SubTask();
            subTask.finalModule();
        } catch (Exception e) {
            throw new CasException(ErrorCode.ERR_HSM_FINALIZE);
        }

    }

    public String processA1(String request) {
        String byPass = StringUtils.rightPad("", 72, "0");
        if (StringUtils.equals(byPass, request)) {
            return StringUtils.rightPad("", 50, "0");
        }
        A1Task task = new A1Task();
        HmcContext hyundaiContext = new HmcContext(task, A1Protocol.Request.class);
        return hyundaiContext.execute(request, charset);
    }

    public String processA2(String request) {
        String byPass = StringUtils.rightPad("", 72, "0");
        if (StringUtils.equals(byPass, request)) {
            return StringUtils.rightPad("", 194, "0");
        }
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
