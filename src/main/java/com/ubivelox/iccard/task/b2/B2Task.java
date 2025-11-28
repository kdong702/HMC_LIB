package com.ubivelox.iccard.task.b2;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.BxTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.util.HexUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "B2", taskName = "기본정보 File Update")
@Slf4j
public class B2Task extends BxTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            B2Protocol.Request b2Req = (B2Protocol.Request) request;
            String keyVersion = "_"+b2Req.getKeyVersion();

            long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL+ keyVersion, transId);
            String apdu = "04DC010C4B";
            String fci = makeFCInformation(b2Req);
            log.info("tst : {}", "65455F201AC8ABB1E6B5BF20202020202020202020202020202020202020204B0E05000000000000000000000000005F240430000101C20100C3020263C4089263141187048110");
            log.info("fci : {}", fci);

            String macData = apdu + b2Req.getCrn().substring(0, 16) + fci;
            log.info("resulted : {}", macData);

            String csn = b2Req.getCsn();
            SecretKeySpec encDkKey = makeDkKey(sessionId, csn, initKeyId, log);
            log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));

            byte[] mac = makeMac(encDkKey, macData, IPkcsMechanism.SEED_VENDOR_CBC, log);
            log.info("mac : {}", HexUtils.toHexString(mac));

            String updateApdu = apdu + fci;
            log.info("updateApdu : {}", updateApdu);
            resultMap.put(Constants.UPDATE_APDU, updateApdu);
            resultMap.put(Constants.MAC, HexUtils.toHexString(mac));
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

    private String makeFCInformation(B2Protocol.Request request) {
        StringBuffer plainData = new StringBuffer();

        String tag01 = "6545";
        plainData.append(tag01);

        byte[] holder = toBytesByLang(request.getCardHolderName().trim()); // 한글과 영어가 올지 몰라 먼저 변환후 나머지, 공백패딩
        byte[] cardHolderPadding = HexUtils.toBytesWithSpacePad(holder, 26);

        String nameNumberTrim = request.getNameNumber().trim();
        byte[] nameId = toBytesByLang(nameNumberTrim);
        byte[] nameIdPadding = HexUtils.addPadding(nameId, 13);
        if (StringUtils.isEmpty(nameNumberTrim)) {
            nameIdPadding = new byte[13]; // 공백일 경우 0으로 채움
        }
        makeTagData(plainData, "5F20", "1A", HexUtils.toHexString(cardHolderPadding)); //tag02
        makeTagData(plainData, "4B", "0E", request.getNameId() + HexUtils.toHexString(nameIdPadding)); //tag03
        makeTagData(plainData, "5F24", "04", request.getExpireDate()); //tag04
        makeTagData(plainData, "C2", "01", "00"); //tag05
        makeTagData(plainData, "C3", "02", request.getBankCode()); //tag06
        makeTagData(plainData, "C4", "08", request.getCsn()); //tag07
        return plainData.toString().toUpperCase();

    }


    private void makeTagData(StringBuffer plainData, String tag, String tagLength, String tagData) {
        String data = StringUtils.rightPad(tagData, Integer.parseInt(tagLength, 16), "0");

        plainData.append(tag);
        plainData.append(tagLength);
        plainData.append(data);
    }


}
