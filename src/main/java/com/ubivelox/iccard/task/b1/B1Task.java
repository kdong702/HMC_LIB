package com.ubivelox.iccard.task.b1;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.HmcSubTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.util.HexUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "B1", taskName = "FCI Update")
public class B1Task extends HmcSubTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            B1Protocol.Request b1Req = (B1Protocol.Request) request;
            String keyVersion = "_"+b1Req.getKeyVersion();
            long initKeyId = findKeyId(sessionId, Constants.FCK_KEY_LABEL_TEST+ keyVersion, transId);
            HashMap<String, String> resultMap = new HashMap();
            String csn = b1Req.getCsn();
            SecretKeySpec encDkKey = makeDkKey(sessionId, csn, initKeyId, log);
            log.info("encDkKey : {}", HexUtils.toHexString(encDkKey.getEncoded()));

            String apdu = "04DC01F42E";
            String crn = b1Req.getCrn().substring(0, 16);
            log.info("crn : {}", crn);
            String fci = makeFci(b1Req.getApplicationLabel(), b1Req.getKeyVersion(), log);
            String macData = apdu + crn + fci;
            log.info("data : {}", macData);
            byte[] mac = makeMac(encDkKey, macData, IPkcsMechanism.SEED_VENDOR_CBC, log);
            log.info("mac : {}", HexUtils.toHexString(mac));

            String updateApdu = apdu + fci;
            log.info("updateApdu : {}", updateApdu);
            resultMap.put(Constants.UPDATE_APDU, updateApdu);
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

    private String makeFci(String label, String keyVersion, CustomLog log) {
        String fciPrefix = "6F288407D4106509900010";
        String proprietary = "A51D5010";
        String labelPad = StringUtils.rightPad(label, 16, ' ');
        log.info("label : [{}]", labelPad);
        byte[] labelBytes = labelPad.getBytes();
        String filePrefix = "BF0C08";
        String standardVersion = "01"; // Statndard Version
        String rfu = "000000000000";
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(fciPrefix);
        stringBuilder.append(proprietary);
        stringBuilder.append(HexUtils.toHexString(labelBytes));
        stringBuilder.append(filePrefix);
        stringBuilder.append(standardVersion);
        stringBuilder.append(keyVersion);
        stringBuilder.append(rfu);
        log.info("fci : {}", stringBuilder.toString());
        return stringBuilder.toString();
    }

    private byte[] makeMac(SecretKeySpec encDkKey, String data, IPkcsMechanism iPkcsMechanism, CustomLog log) {
        byte[] bData = HexUtils.toByteArray(data);
        int blockSize = iPkcsMechanism.getBlockSize();
        byte[] padData = HexUtils.pad80(bData, blockSize);
        log.info("mac data[{}] = {}",padData.length, HexUtils.toHexString(padData));
        byte[] macData = encryptJce(padData, iPkcsMechanism, encDkKey, Constants.NoPadding);

        return HexUtils.findLastBlockData(macData, iPkcsMechanism.getBlockSize(), 4);
    }

    private SecretKeySpec makeDkKey(long sessionId, String csn, long encKeyId, CustomLog log) {
        byte[] encDkData = makeXorDataWithCsn(csn);
        log.info("encDkData[{}] = {}",encDkData.length, HexUtils.toHexString(encDkData));
        return encAndMakeKey(sessionId, encKeyId, encDkData, IPkcsMechanism.SEED_VENDOR_CBC);
    }
}
