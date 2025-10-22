package com.ubivelox.iccard.task.b5;


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

@TaskData(taskCd = "B5", taskName = "금융 IC PIN 변경")
public class B5Task extends BxTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            B5Protocol.Request b5Req = (B5Protocol.Request) request;
            String keyVersion = "_"+b5Req.getKeyVersion();
            long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL + keyVersion, transId);

            String csn = b5Req.getCsn();
            SecretKeySpec encDkKey = makeDkKey(sessionId, csn, initKeyId, log);
            log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));

//            String pin = StringUtils.rightPad(b5Req.getPin(), 8 , ' ');
//            log.info("PIN : [{}]", pin);

            String pin = b5Req.getPin().trim();
            byte[] bPin = HexUtils.padNull(pin.getBytes(), 8);
            log.info("PIN : [{}]", pin);
            log.info("bPin : {}", HexUtils.toHexString(bPin));
            byte[] encPin = encryptJce(HexUtils.pad80(bPin, IPkcsMechanism.SEED_VENDOR_CBC.getBlockSize()), IPkcsMechanism.SEED_VENDOR_CBC, encDkKey, Constants.NoPadding);
            log.info("encPin : {}", HexUtils.toHexString(encPin));

            String encryptData = HexUtils.toHexString(encPin);
            String apdu = "A424010114";
            String crn = b5Req.getCrn().substring(0, 16);
            log.info("crn : {}", crn);
            String macData = apdu + crn + encryptData;
            byte[] mac = makeMac(encDkKey, macData, IPkcsMechanism.SEED_VENDOR_CBC, log);
            log.info("mac : {}", HexUtils.toHexString(mac));

            String putApdu = apdu + encryptData;

            resultMap.put(Constants.PUT_APDU, putApdu);
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
