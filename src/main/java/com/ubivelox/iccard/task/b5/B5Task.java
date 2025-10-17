package com.ubivelox.iccard.task.b5;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.HmcSubTask;
import com.ubivelox.iccard.task.SubTask;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.task.b4.B4Protocol;
import com.ubivelox.iccard.util.HexUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "B5", taskName = "금융 IC PIN 변경")
public class B5Task extends HmcSubTask {

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

    private SecretKeySpec makeDkKey(long sessionId, String csn, long encKeyId, CustomLog log) {
        byte[] dkData = makeXorDataWithCsn(csn);
        log.info("dkData[{}] = {}",dkData.length, HexUtils.toHexString(dkData));
        return encAndMakeKey(sessionId, encKeyId, dkData, IPkcsMechanism.SEED_VENDOR_CBC);
    }

    private byte[] makeMac(SecretKeySpec encDkKey, String data, IPkcsMechanism iPkcsMechanism, CustomLog log) {
        byte[] bData = HexUtils.toByteArray(data);
        int blockSize = iPkcsMechanism.getBlockSize();
        byte[] padData = HexUtils.pad80(bData, blockSize);
        log.info("mac data[{}] = {}",padData.length, HexUtils.toHexString(padData));
        byte[] macData = encryptJce(padData, iPkcsMechanism, encDkKey, Constants.NoPadding);
        log.info("mac enc data[{}] = {}",macData.length, HexUtils.toHexString(macData));
        return HexUtils.findLastBlockData(macData, iPkcsMechanism.getBlockSize(), 4);
    }
}
