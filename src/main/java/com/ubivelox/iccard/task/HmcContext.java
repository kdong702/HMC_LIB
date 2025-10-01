package com.ubivelox.iccard.task;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
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
            log.error(e.getMessage(), e);
            HmcProtocol.Response error = request.generateError(ErrorCode.INVALID_PROTOCOL_LENGTH.getCode());
            String errorResponse = error.getResult(charset);
            log.info("RESULT({})= [{}]", errorResponse.length(),errorResponse);
            log.info("============================ {} ({}) Task End ============================", taskName, taskCd);
            return errorResponse;
        }

        long sessionId = 0;
        try {
            String slotLabel = PropertyReader.getProperty("pkcs11.slot.label");
            sessionId = itask.openSession(slotLabel);
            log.info("Open Session ID : {}", sessionId);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            HmcProtocol.Response error = request.generateError(ErrorCode.ERR_C_OPEN_SESSION.getCode());
            String errorResponse = error.getResult(charset);
            log.info("RESULT({})= [{}]", errorResponse.length(),errorResponse);
            log.info("============================ {} ({}) Task End ============================", taskName, taskCd);
            return errorResponse;
        }


        log.info("REQUEST DATA {}", request);
        HmcProtocol.Response response = itask.doLogic(request, sessionId, transId);
        String result = response.getResult(charset);
        log.info("MASK RESULT= [{}]", response.maskData());
        log.info("RESULT({})= [{}]", result.length(),result);
        log.info("============================ {} ({}) Task End ============================", taskName, taskCd);
        try {
            itask.closeSession(sessionId);
            log.info("Close Session ID : {}", sessionId);
        } catch (BusinessException e) {
            log.error(e.getMessage(), e);
            HmcProtocol.Response error = request.generateError(ErrorCode.ERR_C_CLOSE_SESSION.getCode());
            String errorResponse = error.getResult(charset);
            log.info("RESULT({})= [{}]", errorResponse.length(),errorResponse);
            log.info("============================ {} ({}) Task End ============================", taskName, taskCd);
            return errorResponse;
        }
        return result;


    }

}
