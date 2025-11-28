package com.ubivelox.iccard.task.a1;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.AxTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.util.HexUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "A1", taskName = "CARD Manager 인증")
public class A1Task extends AxTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            A1Protocol.Request a1Req = (A1Protocol.Request) request;
            String keyVersion = "_" + a1Req.getKv();
            long initKeyId = findKeyId(sessionId, Constants.INIT_KEY_LABEL+ keyVersion , transId);
            long bankKeyId = findKeyId(sessionId, Constants.BANK_KEY_LABEL+ keyVersion, transId);

            long[] keyList = new long[]{initKeyId, bankKeyId};

            String kdd = a1Req.getKdd();
            String crn = "";
            String trn = a1Req.getTrn();
            SecretKeySpec encSkKey = null;
            byte[] encSkData;
            byte[] macSkData;
            IPkcsMechanism sessionKeyMechanism;
            int type = 0;
            if (a1Req.isScpType01()) {
                log.info("SCP01 Type");
                log.info("request : {}", a1Req);

                crn = a1Req.getCrn();
                encSkData = makeSkDataWithCrnHrn(crn, trn);
                log.info("encSkData[{}] = {}", encSkData.length, HexUtils.toHexString(encSkData));
                macSkData = makeSkDataWithCrnHrn(crn, trn);
                log.info("macSkData[{}] = {}", macSkData.length, HexUtils.toHexString(macSkData));
                sessionKeyMechanism = IPkcsMechanism.DES3_ECB;
                type = 1;
            } else {
                log.info("SCP02 Type");
                log.info("request : {}", a1Req);

                // parse 하고 난 후에 ac 구분
                String sc = a1Req.getSc();
                crn = sc + a1Req.getCrn() ;
                encSkData = makeSkDataWithTag(sc, 1);
                log.info("encSkData[{}] = {}", encSkData.length, HexUtils.toHexString(encSkData));
                macSkData = makeSkDataWithTag(sc, 2);
                log.info("macSkData[{}] = {}", macSkData.length, HexUtils.toHexString(macSkData));
                sessionKeyMechanism = IPkcsMechanism.DES3_CBC;
                type = 2;
            }

            for (int i = 0; i < keyList.length; i++) {
                initKeyId = keyList[i];
                SecretKeySpec encDkKey = makeDkKey(sessionId, kdd, initKeyId, log, 1);
                log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));
                encSkKey = makeSessionKey(encSkData, encDkKey, sessionKeyMechanism, log);
                log.info("encSkKey : {}", HexUtils.toHexString(encSkKey.getEncoded()));

                byte[] ccMac = makeCcMac(trn, crn, log, encSkKey);
                log.info("ccMac = {}", HexUtils.toHexString(ccMac));
                if (!StringUtils.equalsAnyIgnoreCase(a1Req.getCc(), HexUtils.toHexString(ccMac))) {
                    log.info("{} 번째 시도 CC 검증 실패 CC= [{}], ccMac =[{}]", i+1, a1Req.getCc(), HexUtils.toHexString(ccMac));
                    // 실패시 다음키로 재시도
                    if (i == keyList.length -1) {
                        throw new CasException(ErrorCode.AUTH_FAIL);
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
            resultMap.put(Constants.APDU, HexUtils.toHexString(macApdu));

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





}
