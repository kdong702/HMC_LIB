package com.ubivelox.iccard.task.a2;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.AxTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.util.HexUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "A2", taskName = "CARD MANAGER 인증/Put Key")
public class A2Task extends AxTask {


    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            A2Protocol.Request a2Req = (A2Protocol.Request) request;
            String keyVersion = "_" + a2Req.getKv();
            long initKeyId = findKeyId(sessionId, Constants.INIT_KEY_LABEL + keyVersion, transId);
            long bankKeyId = findKeyId(sessionId, Constants.BANK_KEY_LABEL + keyVersion, transId);

            long[] keyList = new long[]{initKeyId, bankKeyId};

            String kdd = a2Req.getKdd();
            String crn = "";
            String trn = a2Req.getTrn();
            SecretKeySpec encSkKey = null;
            byte[] encSkData;
            byte[] macSkData;
            byte[] kekSkData;
            IPkcsMechanism sessionKeyMechanism;
            int type = 0;
            String putAdpuPrefix;
            if (a2Req.isScpType01()) {
                log.info("SCP01 Type");
                log.info("request : {}", a2Req);

                crn = a2Req.getCrn();
                encSkData = makeSkDataWithCrnHrn(crn, trn);
                macSkData = makeSkDataWithCrnHrn(crn, trn);
                kekSkData = makeSkDataWithCrnHrn(crn, trn);
                sessionKeyMechanism = IPkcsMechanism.DES3_ECB;
                type = 1;
                putAdpuPrefix = "8110";
            } else {
                log.info("SCP02 Type");
                log.info("request : {}", a2Req);

                // parse 하고 난 후에 ac 구분
                String sc = a2Req.getSc();
                crn = sc + a2Req.getCrn() ;
                encSkData = makeSkDataWithTag(sc, 1);
                macSkData = makeSkDataWithTag(sc, 2);
                kekSkData = makeSkDataWithTag(sc, 3);
                sessionKeyMechanism = IPkcsMechanism.DES3_CBC;
                type = 2;
                putAdpuPrefix = "8010";
            }

            for (int i = 0; i < keyList.length; i++) {
                initKeyId = keyList[i];
                SecretKeySpec encDkKey = makeDkKey(sessionId, kdd, initKeyId, log, 1);
                log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));
                encSkKey = makeSessionKey(encSkData, encDkKey, sessionKeyMechanism, log);
                log.info("encSkKey : {}", HexUtils.toHexString(encSkKey.getEncoded()));

                byte[] ccMac = makeCcMac(trn, crn, log, encSkKey);
                log.info("ccMac = {}", HexUtils.toHexString(ccMac));
                if (!StringUtils.equalsAnyIgnoreCase(a2Req.getCc(), HexUtils.toHexString(ccMac))) {
                    log.info("{} 번째 시도 CC 검증 실패 CC= [{}], ccMac =[{}]", i+1, a2Req.getCc(), HexUtils.toHexString(ccMac));
                    // 실패시 다음키로 재시도
                    if (i == keyList.length -1) {
                        throw new BusinessException(ErrorCode.AUTH_FAIL);
                    }
                } else {
                    // 성공시 종료
                    break;
                }
            }

            byte[] cc2Mac = makeCcMac(crn, trn, log, encSkKey);
            log.info("cc2Mac = {}", HexUtils.toHexString(cc2Mac));
            SecretKeySpec macDkKey = makeDkKey(sessionId, kdd, initKeyId, log, 2);
            log.info("macDkKey : {}", HexUtils.toHexString(macDkKey.getEncoded()));
            SecretKeySpec macSkKey = makeSessionKey(macSkData, macDkKey, sessionKeyMechanism, log);
            log.info("macSkKey : {}", HexUtils.toHexString(macSkKey.getEncoded()));
            // Todo mac 생성 방식 SCP01, 02 다름
            byte[] macApdu = makeMacWithApdu(macSkKey, cc2Mac, log, type);
            log.info("macApdu[{}] = {}",macApdu.length, HexUtils.toHexString(macApdu));
            resultMap.put(Constants.AUTH_APDU, HexUtils.toHexString(macApdu));

            SecretKeySpec kekDkKey = makeDkKey(sessionId, kdd, initKeyId, log, 3);
            log.info("kekDkKey : {}", HexUtils.toHexString(kekDkKey.getEncoded()));
            SecretKeySpec kekSkKey = makeSessionKey(kekSkData, kekDkKey, sessionKeyMechanism, log);
            log.info("kekSkKey : {}", HexUtils.toHexString(kekSkKey.getEncoded()));

            SecretKeySpec encBankDkKey = makeDkKey(sessionId, kdd, bankKeyId, log, 1);
            SecretKeySpec macBankDkKey = makeDkKey(sessionId, kdd, bankKeyId, log, 2);
            SecretKeySpec kekBankDkKey = makeDkKey(sessionId, kdd, bankKeyId, log, 3);
            log.info("encBankDkKey : {}", HexUtils.toHexString(encBankDkKey.getEncoded()));
            log.info("macBankDkKey : {}", HexUtils.toHexString(macBankDkKey.getEncoded()));
            log.info("kekBankDkKey : {}", HexUtils.toHexString(kekBankDkKey.getEncoded()));
            // kcv 계산하는 키 값이 scp01, 02 다름
            SecretKeySpec encKey = null;
            if (type == 1) {
                encKey= kekDkKey;
            } else {
                encKey = kekSkKey;
            }

            byte[] encBankDk = encryptJce(encBankDkKey.getEncoded(), IPkcsMechanism.DES3_ECB, encKey, Constants.NoPadding);
            byte[] macBankDk = encryptJce(macBankDkKey.getEncoded(), IPkcsMechanism.DES3_ECB, encKey, Constants.NoPadding);
            byte[] kekBankDk = encryptJce(kekBankDkKey.getEncoded(), IPkcsMechanism.DES3_ECB, encKey, Constants.NoPadding);
            log.info("encBankDkValue : {}", HexUtils.toHexString(encBankDk));
            log.info("macBankDkValue : {}", HexUtils.toHexString(macBankDk));
            log.info("kekBankDkValue : {}", HexUtils.toHexString(kekBankDk));
            byte[] kcvEnc = calKCV(encBankDkKey, IPkcsMechanism.DES3_ECB);
            byte[] kcvMac = calKCV(macBankDkKey, IPkcsMechanism.DES3_ECB);
            byte[] kcvKek = calKCV(kekBankDkKey, IPkcsMechanism.DES3_ECB);
            log.info("kcv_enc : {}", HexUtils.toHexString(kcvEnc));
            log.info("kcv_mac : {}", HexUtils.toHexString(kcvMac));
            log.info("kcv_kek : {}", HexUtils.toHexString(kcvKek));

            // TODO 8010 대신 8110
            String putApdu = "80D8" + a2Req.getKv() + "814301" +
                    putAdpuPrefix +HexUtils.toHexString(encBankDk).substring(0,32) +
                    "03" + HexUtils.toHexString(kcvEnc) +
                    putAdpuPrefix + HexUtils.toHexString(macBankDk).substring(0,32) +
                    "03" + HexUtils.toHexString(kcvMac) +
                    putAdpuPrefix + HexUtils.toHexString(kekBankDk).substring(0,32) +
                    "03" + HexUtils.toHexString(kcvKek);
            resultMap.put(Constants.PUT_APDU, putApdu);

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
