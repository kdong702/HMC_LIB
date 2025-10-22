package com.ubivelox.iccard.task.b3;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.BxTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.util.HexUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "B3", taskName = "계좌정보 File Update")
public class B3Task extends BxTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            B3Protocol.Request b3Req = (B3Protocol.Request) request;
            String keyVersion = "_"+b3Req.getKeyVersion();

            long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL+ keyVersion, transId);

            String csn = b3Req.getCsn();
            SecretKeySpec encDkKey = makeDkKey(sessionId, csn, initKeyId, log);
            log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));

            String accountNumber = b3Req.getAccountNumber().replace("=","D");
            log.info("accountNumber : {}", accountNumber);
            String accountStatusCode = b3Req.getAccountStatusCode();
            String startPosition = b3Req.getStartPosition();
            String accountCount = b3Req.getAccountCount();

            String plainData = "C13E" + accountStatusCode + "B" + accountNumber + "F00" + startPosition + accountCount + "0000000000";
            log.info("plainData[{}] : {}", plainData.length(), plainData);


            String crn = b3Req.getCrn().substring(0, 16);
            // pad 0 10개 제거, length 2 추가
            int length = (plainData.length() - 10 + crn.length() + 2 ) / 2;
            String lengthHex = String.format("%02X", length);
            String apdu = "04DC" + b3Req.getRecord() + "14" + lengthHex;
            log.info("apdu[{}] : {}", apdu.length(), apdu);


            String macData = apdu + crn + plainData;
            log.info("macData[{}] : {}", macData.length(), macData);
            byte[] mac = makeMac(encDkKey, macData, IPkcsMechanism.SEED_VENDOR_CBC, log);

            log.info("mac : {}", HexUtils.toHexString(mac));

            String updateAdpu = apdu + plainData;

            resultMap.put(Constants.UPDATE_APDU, updateAdpu);
            resultMap.put(Constants.MAC, HexUtils.toHexString(mac));
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
