package com.ubivelox.iccard.task;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.util.PropertyReader;
import com.ubivelox.iccard.util.StreamReader;

public class HmcContext<T extends HmcProtocol.Request> {

    private final ITask itask;
    private final Class<T> tclass;

    public HmcContext(ITask itask, Class<T> clazz) {
        this.itask = itask;
        this.tclass = clazz;
    }

    public String execute(String hexData, String charset){
        CustomLog log = new CustomLog();
        String transId = log.getUuid();

        String taskName = "";
        String taskCd = "";
        TaskData taskData = itask.getClass().getDeclaredAnnotation(TaskData.class);

        if (taskData != null) {
            taskName = taskData.taskName();
            taskCd = taskData.taskCd();
            log.info("============================ {} ({}) Task Start ============================", taskName, taskCd);
        }
        log.info("Request({})= [{}]", hexData.length(), hexData);
        HmcProtocol.Request request = null;
        try {
            request = tclass.getDeclaredConstructor().newInstance();
            request.read(new StreamReader(hexData, charset));
        } catch (Exception e) {
            extracted(log, e, ErrorCode.INVALID_PROTOCOL_LENGTH, taskName, taskCd);
        }

        long sessionId = 0;
        try {
            String slotLabel = PropertyReader.getProperty("pkcs11.slot.label");
            sessionId = itask.openSession(slotLabel);
            log.info("Open Session ID : {}", sessionId);
        } catch (Exception e) {
            extracted(log, e, ErrorCode.ERR_C_OPEN_SESSION, taskName, taskCd);
        }


        log.info("REQUEST DATA {}", request);
        String result = "";
        try {
            HmcProtocol.Response response = itask.doLogic(request, sessionId, transId);
            result = response.getResult(charset);
            log.info("MASK RESULT= [{}]", response.maskData());
            log.info("RESULT({})= [{}]", result.length(),result);
            log.info("============================ {} ({}) Task End ============================", taskName, taskCd);
        } catch (Exception e) {
            extracted(log, e, ErrorCode.ERR_TASK_PROCESS, taskName, taskCd);
        }

        try {
            itask.closeSession(sessionId);
            log.info("Close Session ID : {}", sessionId);
        } catch (Exception e) {
            extracted(log, e, ErrorCode.ERR_C_CLOSE_SESSION, taskName, taskCd);
        }
        return result;


    }

    private static void extracted(CustomLog log, Exception e, ErrorCode errCCloseSession, String taskName, String taskCd) {
        log.error(e.getMessage(), e);
        log.info("============================ {} ({}) Task Error ============================", taskName, taskCd);
        ErrorCode errorCode;
        if (e instanceof CasException) {
            errorCode = ((CasException) e).getErrorCode();
        } else {
            errorCode = errCCloseSession;
        }
        throw new CasException(errorCode, e);
    }

}
