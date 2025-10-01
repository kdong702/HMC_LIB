package com.ubivelox.iccard.task;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.task.protocol.HmcProtocol;

import java.util.HashMap;

@TaskData(taskCd = "B4", taskName = "금융 IC Key 변경")
public class B4Task extends SubTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            resultMap.put(Constants.PUT_APDU, "00A4040007A000000003101000");
            resultMap.put(Constants.MAC, "12345678910");
            HmcProtocol.Response response = request.generateResponse(request, Constants.SUCCESS, resultMap);
            log.info("RESPONSE DATA {}", response);
            return response;
        } catch (BusinessException e) {
            log.error(e.getMessage(), e);
            HmcProtocol.Response responseError = request.generateError(e.getErrorCode().getCode());
            log.info("RESPONSE ERROR DATA {}", responseError);
            return responseError;
        }
    }
}
