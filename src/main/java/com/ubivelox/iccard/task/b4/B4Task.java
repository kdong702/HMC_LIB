package com.ubivelox.iccard.task.b4;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.BxTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.util.HexUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "B4", taskName = "금융 IC Key 변경")
public class B4Task extends BxTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            B4Protocol.Request b4Req = (B4Protocol.Request) request;
            SecretKeySpec dkKey;
            String csn = b4Req.getCsn();
            byte[] enc;
            if (StringUtils.equals(b4Req.getKeyVersion(), "00")) {
                byte[] initKeyData = HexUtils.toByteArray("16151413121110090807060504030201");
                dkKey = makeKeyHandleWithEncData(initKeyData, IPkcsMechanism.SEED_VENDOR_CBC);
                log.info("dkKey : {}", HexUtils.toHexString(dkKey.getEncoded()));

                long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL + "_01", transId);
                SecretKeySpec encDkKey = makeDkKey(sessionId, csn, initKeyId, log);
                log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));

                enc = encryptJce(encDkKey.getEncoded(), IPkcsMechanism.SEED_VENDOR_CBC, dkKey, Constants.NoPadding);
            } else {
                String keyVersion = "_"+b4Req.getKeyVersion();
                long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL + keyVersion, transId);

                dkKey = makeDkKey(sessionId, csn, initKeyId, log);
                log.info("dkKey : {}", HexUtils.toHexString(dkKey.getEncoded()));

                enc = encryptJce(dkKey.getEncoded(), IPkcsMechanism.SEED_VENDOR_CBC, dkKey, Constants.NoPadding);
            }

            String encryptData = HexUtils.toHexString(enc);
            log.info("encryptData : {}", encryptData);

            String apdu = "A424000114";
            String crn = b4Req.getCrn().substring(0, 16);
            log.info("crn : {}", crn);
            String macData = apdu + crn + encryptData;

            byte[] mac = makeMac(dkKey, macData, IPkcsMechanism.SEED_VENDOR_CBC, log);
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
