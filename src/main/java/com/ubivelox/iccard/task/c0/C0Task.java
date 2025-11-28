package com.ubivelox.iccard.task.c0;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.CxTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.util.HexUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "C0", taskName = "계좌 비밀번호 복호화")
public class C0Task extends CxTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            C0Protocol.Request c0Req = (C0Protocol.Request) request;
            String keyVersion = "_"+c0Req.getKeyVersion();
            long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL + keyVersion, transId);

            String csn = c0Req.getCsn();
            SecretKeySpec encDkKey = makeDkKey(sessionId, csn, initKeyId, log);
            log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));

            String crn = c0Req.getCrn();
            log.info("crn : {}", crn);
            SecretKeySpec tempKey = encAndMakeKey(crn, encDkKey, IPkcsMechanism.SEED_VENDOR_CBC, Constants.NoPadding, log);
            log.info("tempKey : {}", HexUtils.toHexString(tempKey.getEncoded()));

            String trn = c0Req.getTrn();
            log.info("trn : {}", trn);
            SecretKeySpec sessionKey = encAndMakeKey(trn, tempKey, IPkcsMechanism.SEED_VENDOR_CBC, Constants.NoPadding, log);
            log.info("sessionKey : {}", HexUtils.toHexString(sessionKey.getEncoded()));

            String pin = c0Req.getEncPwd();
            log.info("PIN : [{}]", pin);
            String decryptPin = decryptUnpad80(pin, sessionKey, IPkcsMechanism.SEED_VENDOR_CBC, log);

            resultMap.put(Constants.PIN, decryptPin);
            HmcProtocol.Response response = request.generateResponse(request, Constants.SUCCESS, resultMap);
            log.info("RESPONSE DATA {}", response);
            return response;
        } catch (CasException e) {
            log.error(e.getMessage(), e);
            HmcProtocol.Response responseError = request.generateError(e.getErrorCode().getCode());
            log.info("RESPONSE ERROR DATA {}", responseError);
            throw e;
        }
    }

    private SecretKeySpec encAndMakeKey(String plain, SecretKeySpec tempKey, IPkcsMechanism iPkcsMechanism, String padding, CustomLog log) {
        byte[] bPlain = HexUtils.toByteArray(plain);
        log.info("bPlain : {}", HexUtils.toHexString(bPlain));
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

}
