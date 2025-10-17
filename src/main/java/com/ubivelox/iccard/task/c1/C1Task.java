package com.ubivelox.iccard.task.c1;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.HmcSubTask;
import com.ubivelox.iccard.task.SubTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.task.c0.C0Protocol;
import com.ubivelox.iccard.util.HexUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "C1", taskName = "비밀번호, 계좌번호, 출금금액 복호화")
public class C1Task extends HmcSubTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            C1Protocol.Request c1Req = (C1Protocol.Request) request;
            String keyVersion = "_"+c1Req.getKeyVersion();
            long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL + keyVersion, transId);

            String csn = c1Req.getCsn();
            SecretKeySpec encDkKey = makeDkKey(sessionId, csn, initKeyId, log);
            log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));

            String crn = c1Req.getCrn1();
            log.info("crn : {}", crn);
            SecretKeySpec tempKey = encAndMakeKey(crn, encDkKey, IPkcsMechanism.SEED_VENDOR_CBC, Constants.NoPadding, log);
            log.info("tempKey : {}", HexUtils.toHexString(tempKey.getEncoded()));

            String trn = c1Req.getTrn();
            log.info("trn : {}", trn);
            SecretKeySpec sessionKey = encAndMakeKey(trn, tempKey, IPkcsMechanism.SEED_VENDOR_CBC, Constants.NoPadding, log);
            log.info("sessionKey : {}", HexUtils.toHexString(sessionKey.getEncoded()));

            String pin = c1Req.getEncPwd();
            log.info("PIN : [{}]", pin);
            String decryptPin = decryptUnpad80(pin, sessionKey, IPkcsMechanism.SEED_VENDOR_CBC, log);

            resultMap.put(Constants.PIN, decryptPin);
            resultMap.put(Constants.ACCOUNT_NUMBER, "12345678910");
            resultMap.put(Constants.AMOUNT, "100000");
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

    private SecretKeySpec encAndMakeKey(String plain, SecretKeySpec tempKey, IPkcsMechanism iPkcsMechanism, String padding, CustomLog log) {
        byte[] bPlain = HexUtils.toByteArray(plain);
        byte[] encPlain = encryptJce(bPlain, iPkcsMechanism , tempKey, padding);
        log.info("encPlain : {}", HexUtils.toHexString(encPlain));
        return makeKeyHandleWithEncData(encPlain, iPkcsMechanism);
    }

    private String decryptUnpad80(String pin,  SecretKeySpec sessionKey, IPkcsMechanism iPkcsMechanism, CustomLog log) {
        byte[] bPin = HexUtils.toByteArray(pin);
        log.info("bPin : {}", HexUtils.toHexString(bPin));
        byte[] decPin = decryptJce(bPin, iPkcsMechanism, sessionKey, Constants.NoPadding);
        log.info("decPin : {}", HexUtils.toHexString(decPin));
        String decryptPin = new String(HexUtils.unpad80(decPin, iPkcsMechanism.getBlockSize()));
        log.info("decryptPin : [{}]", decryptPin);
        return decryptPin;
    }

    private SecretKeySpec makeDkKey(long sessionId, String csn, long encKeyId, CustomLog log) {
        byte[] dkData = makeXorDataWithCsn(csn);
        log.info("dkData[{}] = {}",dkData.length, HexUtils.toHexString(dkData));
        return encAndMakeKey(sessionId, encKeyId, dkData, IPkcsMechanism.SEED_VENDOR_CBC);
    }
}
