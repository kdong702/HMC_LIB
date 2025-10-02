package com.ubivelox.iccard.task.a2;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.task.HmcProtocol;
import com.ubivelox.iccard.task.HmcSubTask;
import com.ubivelox.iccard.util.ByteUtils;
import com.ubivelox.iccard.util.HexUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;

@TaskData(taskCd = "A2", taskName = "CARD MANAGER 인증/Put Key")
public class A2Task extends HmcSubTask {


    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            long initKeyId = findObj(sessionId, Constants.INIT_KEY_LABEL, transId);
            long bankKeyId = findObj(sessionId, Constants.BANK_KEY_LABEL, transId);

            long[] keyList = new long[]{initKeyId, bankKeyId};
            HashMap<String, String> resultMap = new HashMap();
            A2Protocol.Request a2Req = (A2Protocol.Request) request;
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
            String kv = a2Req.getKv();
            // TODO 8010 대신 8110
            String putApdu = "80D8" + kv + "814301" +
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

    private byte[] makeCcMac(String trn, String crn, CustomLog log, SecretKeySpec encSkKey) {
        byte[] cc = makeCcData(trn, crn, log, encSkKey);
        log.info("cc = {}", HexUtils.toHexString(cc));
        byte[] ccMac = HexUtils.findLastBlockData(cc, IPkcsMechanism.DES3_CBC.getBlockSize(), 8);

        return ccMac;
    }

    private byte[] makeCcData(String hrn, String crn, CustomLog log, SecretKeySpec encSkKey) {
        byte[] cc1Data = makeCcDataWithPad(hrn, crn);
        log.info("ccData[{}] = {}",cc1Data.length, HexUtils.toHexString(cc1Data));
        return encryptJce(cc1Data, IPkcsMechanism.DES3_CBC, encSkKey, Constants.NoPadding);
    }

    private SecretKeySpec makeSessionKey(String sc, SecretKeySpec encDkKey, CustomLog log, int tagFlag) {
        byte[] skData = makeSkDataWithTag(sc, tagFlag);
        byte[] encSkData = encryptJce(skData, IPkcsMechanism.DES3_CBC, encDkKey, Constants.NoPadding);
        log.info("encSkData[{}] = {}", encSkData.length, HexUtils.toHexString(encSkData));
        // TODO Chiper 는 DDES 가 없으므로 3DES 로 처리 후 가공 필요
        byte[] encSk16Data = ByteUtils.cutByteArray(encSkData, 0, 16);
        byte[] encSk24Data = ByteUtils.copyArray(encSk16Data, encSk16Data, 16, 8);
        return createObjJce(encSk24Data, IPkcsMechanism.DES3_CBC);
    }

    private SecretKeySpec makeSessionKey(byte[] skData, SecretKeySpec encDkKey, IPkcsMechanism mechanism, CustomLog log) {
        byte[] encSkData = encryptJce(skData, mechanism, encDkKey, Constants.NoPadding);
        log.info("encSkData[{}] = {}", encSkData.length, HexUtils.toHexString(encSkData));
        // TODO Chiper 는 DDES 가 없으므로 3DES 로 처리 후 가공 필요
        byte[] encSk16Data = ByteUtils.cutByteArray(encSkData, 0, 16);
        byte[] encSk24Data = ByteUtils.copyArray(encSk16Data, encSk16Data, 16, 8);
        return createObjJce(encSk24Data, mechanism);
    }

    private SecretKeySpec makeSessionKey(String crn, String hrn, SecretKeySpec encDkKey, CustomLog log) {
        byte[] skData = makeSkDataWithCrnHrn(crn, hrn); // TODO 여기 한 부분이 다른듯?

        byte[] encSkData = encryptJce(skData, IPkcsMechanism.DES3_ECB, encDkKey, Constants.NoPadding);
        log.info("encSkData[{}] = {}", encSkData.length, HexUtils.toHexString(encSkData));
        // TODO Chiper 는 DDES 가 없으므로 3DES 로 처리 후 가공 필요
        byte[] encSk16Data = ByteUtils.cutByteArray(encSkData, 0, 16);
        byte[] encSk24Data = ByteUtils.copyArray(encSk16Data, encSk16Data, 16, 8);
        return createObjJce(encSk24Data, IPkcsMechanism.DES3_ECB);
    }
    private SecretKeySpec makeDkKey(long sessionId, String kdd, long encKeyId, CustomLog log, int tagFlag) {
        byte[] encDkData = makeDkDataWithTag(kdd, tagFlag);
        log.info("encDkData[{}] = {}",encDkData.length, HexUtils.toHexString(encDkData));
        byte[] encDk24Data = ByteUtils.copyArray(encDkData, encDkData, 16, 8);
        return encAndMakeKey(sessionId, encKeyId, encDk24Data, IPkcsMechanism.DES2_DES3_ECB);
    }

    protected byte[] getMacPad(byte[] hostCryptogram) {
        byte[] apdu = new byte[]{(byte) 0x84, (byte) 0x82, (byte) 0x00, (byte) 0x00, (byte) 0x10};
        return ByteUtils.copyArrayWithPad(apdu, hostCryptogram, 16);
    }

    protected byte[] makeMacWithApdu(SecretKeySpec sessionKey, byte[] hostCryptogram,  CustomLog log, int type) {
        byte[] apdu = new byte[]{(byte) 0x84, (byte) 0x82, (byte) 0x00, (byte) 0x00, (byte) 0x10};
        byte[] bMacPad = getMacPad(hostCryptogram);
        log.info("bMacPad[{}]: {}", bMacPad.length, HexUtils.toHexString(bMacPad));

        if (type == 1) {
            byte[] mac = encryptJce(bMacPad, IPkcsMechanism.DES3_CBC, sessionKey, Constants.NoPadding);
            log.info("mac: {}", HexUtils.toHexString(mac));
            byte[] macApdu = ByteUtils.copyArrays(apdu, hostCryptogram, HexUtils.findLastBlockData(mac, 8, 8));
            log.info("macApdu[{}]: {}", macApdu.length, HexUtils.toHexString(macApdu));
            return macApdu;
        } else {

            byte[] encData = new byte[8];
            byte[] temp = new byte[8];
            byte[] encXTemp = new byte[8];
            SecretKeySpec aHandle = createObjJce(ByteUtils.cutByteArray(sessionKey.getEncoded(), 0, 8), IPkcsMechanism.DES_ECB);

            for (int idx = 0; idx < bMacPad.length; idx += IPkcsMechanism.DES_ECB.getBlockSize()) {
                System.arraycopy(bMacPad, idx, temp, 0, 8);
                encXTemp = ByteUtils.xor(temp, encData);
                encData = encryptJce(encXTemp, IPkcsMechanism.DES_ECB, aHandle, Constants.NoPadding);
            }
            byte[] mac = encryptJce(encXTemp, IPkcsMechanism.DES3_ECB, sessionKey, Constants.NoPadding);
            log.info("mac: {}", HexUtils.toHexString(mac));
            byte[] macApdu = ByteUtils.copyArrays(apdu, hostCryptogram, mac);
            log.info("macApdu[{}]: {}", macApdu.length, HexUtils.toHexString(macApdu));
            return macApdu;
        }
    }

//    private String makeCdolData18(Auth.Request request) {
//        StringBuilder sb = findTag(request);
//        sb.append(request.findTagValue(AIP));
//        sb.append(request.findTagValue(ATC));
//        sb.append(request.findTagValue(IAD).trim());
//        return sb.toString();
//    }
//
//    private String makeCdolData10(Auth.Request request, String cvr) {
//        StringBuilder sb = findTag(request);
//        sb.append(request.findTagValue(AIP));
//        sb.append(request.findTagValue(ATC));
//        sb.append(cvr);
//        return sb.toString();
//    }
//    private StringBuilder findTag(Auth.Request request) {
//        StringBuilder sb = new StringBuilder();
//        sb.append(request.findTagValue(CRYPTO_AMOUNT));
//        sb.append(request.findTagValue(CRYPTO_CASH_AMOUNT));
//        sb.append(request.findTagValue(TML_COUNTRY_CODE));
//        sb.append(request.findTagValue(TVR));
//        sb.append(request.findTagValue(CRYPTO_CURR_CODE));
//        sb.append(request.findTagValue(TML_TRANS_DATE));
//        sb.append(request.findTagValue(CTT));
//        sb.append(request.findTagValue(UNPR_NO));
//        return sb;
//    }
//
//    private String checkCvnType(String cvn) {
//        if (StringUtils.equals(cvn, CVN_10_MODE)) {
//            return CVN_10_MODE;
//        } else if (StringUtils.equals(cvn, CVN_18_MODE)) {
//            return CVN_18_MODE;
//        } else {
//            throw new LibException(LibErrorCode.INVALID_CVN);
//        }
//    }
//
//    protected byte[] makeDerivationData(String pan, String panSeq) {
//        String rightFromPanAndPanSeq = pan.substring(pan.length() - 14, pan.length()) + panSeq; // 오른쪽 정렬
//        byte[] inputDataA = HexUtils.toByteArray(rightFromPanAndPanSeq);
//        byte[] inputDataB = ByteUtils.xor(inputDataA);
//        log.debug("inputDataA: {}", HexUtils.toHexString(inputDataA));
//        log.debug("inputDataB: {}", HexUtils.toHexString(inputDataB));
//
//        byte[] bDkData = ByteUtils.copyArray(inputDataA, inputDataB);
//        log.debug("bDKData: {}", HexUtils.toHexString(bDkData));
//        return bDkData;
//    }
//
//    protected void makeUdkKeyAAndDES3(byte[] data, HashMap<String, SecretKeySpec> keyMap, CustomLog logger) {
//        byte[] dataA = ByteUtils.cutByteArray(data, 0, 8);
//        SecretKeySpec handleA = makeKeyHandleWithEncData(dataA, PkcsMechanism.DES_ECB);
//
//        byte[] dataB = ByteUtils.cutByteArray(data, 8, 8);
//        SecretKeySpec handleB = makeKeyHandleWithEncData(dataB,  PkcsMechanism.DES_ECB);
//
//        byte[] dataDes3 = ByteUtils.copyArray(data, dataA);
//        logger.log("udk_handle Data = {}", HexUtils.toHexString(HexUtils.makeOddParity(dataDes3)));
//        SecretKeySpec handleDes3 = makeKeyHandleWithEncData(dataDes3, PkcsMechanism.DES3_ECB);
//
//        keyMap.put(UDK_A_HANDLE, handleA);
//        keyMap.put(UDK_B_HANDLE, handleB);
//        keyMap.put(UDK_HANDLE, handleDes3);
//    }
//
//    protected SecretKeySpec makeKeyHandleWithEncData(byte[] bEncData, PkcsMechanism pkcsMechanism) {
//        if (StringUtils.equals(pkcsMechanism.getParityYn(), YES)) {
//            bEncData = HexUtils.makeOddParity(bEncData);
//        }
//        SecretKeySpec keyHandle = createObjJce(bEncData, pkcsMechanism);
//        return keyHandle;
//    }
//
//    protected byte[] makeSessionFData(String atc) {
//        byte[] fDataA = ByteUtils.toFillRight(HexUtils.toByteArray(atc), (byte)0x00, 8);
//        fDataA[2] = (byte)0xF0;
//        byte[] fDataB = ByteUtils.toFillRight(HexUtils.toByteArray(atc), (byte)0x00, 8);
//        fDataB[2] = (byte)0x0F;
//        log.debug("F1: {}", HexUtils.toHexString(fDataA));
//        log.debug("F2: {}", HexUtils.toHexString(fDataB));
//
//        return ByteUtils.copyArray(fDataA, fDataB);
//    }
//
//
//    protected void makeSessionKeyAAndDES3(SecretKeySpec udkHandle, byte[] data, HashMap<String, SecretKeySpec> keyMap, CustomLog logger) throws TaskException {
//        byte[] dataA = ByteUtils.cutByteArray(data, 0, 8);
//        byte[] dataB = ByteUtils.cutByteArray(data, 8, 8);
//
//        byte[] sessionAData = encryptJce(dataA, PkcsMechanism.DES3_ECB, udkHandle, NoPadding );
//        SecretKeySpec sessionAHandle = makeKeyHandleWithEncData(sessionAData, PkcsMechanism.DES_ECB);
//
//        byte[] sessionBData = encryptJce(dataB, PkcsMechanism.DES3_ECB, udkHandle, NoPadding );
////        SecretKeySpec sessionBHandle = makeKeyHandleWithEncData(sessionBData, PkcsMechanism.DES_ECB);
//
//        byte[] sessionData = ByteUtils.copyArrays(sessionAData, sessionBData, sessionAData);
//        SecretKeySpec sessionHandle = makeKeyHandleWithEncData(sessionData, PkcsMechanism.DES3_ECB);
//        logger.log("sessionData = {}", HexUtils.toHexString(HexUtils.makeOddParity(sessionData)));
//
//        keyMap.put(SESSION_A_HANDLE, sessionAHandle);
//        keyMap.put(SESSION_HANDLE, sessionHandle);
//    }
//
//    protected byte[] xorEncDES(SecretKeySpec aHandle, SecretKeySpec handle, byte[] array) {
//        byte[] encData = new byte[8];
//        byte[] temp = new byte[8];
//        byte[] encXTemp = new byte[8];
//
//        for (int idx = 0; idx < array.length; idx += PkcsMechanism.DES_ECB.getBlockSize()) {
//            System.arraycopy(array, idx, temp, 0, 8);
//            encXTemp = xor(encData, temp);
//            encData = encryptJce(encXTemp, PkcsMechanism.DES_ECB, aHandle, NoPadding );
//            log.debug("xorEncDes(), tempInput: {}, outPut: {}", HexUtils.toHexString(temp), HexUtils.toHexString(encData));
//
//        }
//        return encryptJce(encXTemp, PkcsMechanism.DES3_ECB, handle, NoPadding);
//    }
//
//    protected void checkArqc(byte[] bArqc, byte[] calcARQC) {
//        boolean isSameARQC = Arrays.equals(bArqc, calcARQC);
//        log.debug("reqARQC: {}, calcARQC: {}, isSameARQC: {}", HexUtils.toHexString(bArqc), HexUtils.toHexString(calcARQC), isSameARQC);
//        if (!isSameARQC) {
//            throw new LibException(LibErrorCode.ARQC_FAIL);
//        }
//    }
//
//    private byte[] makeArpc18(SecretKeySpec udkAHandle, SecretKeySpec udkHandle, byte[] bArqc) {
//        String csu = "00800000";
//        byte[] bCsu = HexUtils.toByteArray(csu);
//        byte[] bArpcData = HexUtils.pad80(ByteUtils.copyArray(bArqc, bCsu), PkcsMechanism.DES_ECB.getBlockSize());
//        log.debug("ARPCData: {}", HexUtils.toHexString(bArpcData));
//
//        byte[] decTemp = xorEncDecDES(udkAHandle, udkHandle, bArpcData);
//        byte[] first4DecTemp = ByteUtils.cutByteArray(decTemp, 0, 4);
//        byte[] arpcResult = ByteUtils.copyArray(first4DecTemp, HexUtils.toByteArray(csu));
//        log.debug("ARPC: {}", HexUtils.toHexString(arpcResult));
//        return arpcResult;
//    }
//
//    private byte[] makeArpc10(SecretKeySpec udkHandle, byte[] calcARQC) {
//        byte[] bArc = ByteUtils.toFillLeft(new byte[6], (byte)0x30, 8);
//        byte[] xorARC = xor(calcARQC, bArc);
//        log.debug("ARC: {}, xorARC: {}", HexUtils.toHexString(bArc), HexUtils.toHexString(xorARC));
//
//        byte[] bArpc = encryptJce(xorARC, PkcsMechanism.DES3_ECB, udkHandle, NoPadding);
//        log.debug("bARPC: {}",  HexUtils.toHexString(bArpc));
//        return bArpc;
//    }
//
//    private byte[] xorEncDecDES(SecretKeySpec aHandle, SecretKeySpec bHandle, byte[] array) {
//        byte[] encData = new byte[8];
//        byte[] temp = new byte[8];
//        byte[] encXTemp = new byte[8];
//
//        for (int idx = 0; idx < array.length; idx += PkcsMechanism.DES_ECB.getBlockSize()) {
//            if (idx + PkcsMechanism.DES_ECB.getBlockSize() > array.length) {
//                break;
//            }
//            System.arraycopy(array, idx, temp, 0, 8);
//            encXTemp = xor(encData, temp);
//            encData = encryptJce(encXTemp, PkcsMechanism.DES_ECB, aHandle, NoPadding);
//            log.debug("xorEncDecDes(), tempInput: {}, outPut: {}", HexUtils.toHexString(temp), HexUtils.toHexString(encData));
//
//        }
////        return decrypt(sessionId, handle, encXTemp, IPkcsMechanism.DES3_ECB);
//
////        byte[] data = encrypt(sessionId, aHandle, encXTemp, IPkcsMechanism.DES_ECB);
//        byte[] decData = decryptJce(encData, PkcsMechanism.DES_ECB, bHandle, NoPadding);
//        byte[] decData2 = encryptJce(decData, PkcsMechanism.DES_ECB, aHandle, NoPadding);
//        return decData2;
//    }


}
