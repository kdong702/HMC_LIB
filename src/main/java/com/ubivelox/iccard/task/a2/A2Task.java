package com.ubivelox.iccard.task;


import com.ubivelox.iccard.annotation.TaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.task.protocol.A2;
import com.ubivelox.iccard.task.protocol.HmcProtocol;

import java.util.HashMap;

@TaskData(taskCd = "A2", taskName = "CARD MANAGER 인증/Put Key")
public class A2Task extends SubTask {

    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        CustomLog log = new CustomLog(transId);
        try {
            HashMap<String, String> resultMap = new HashMap();
            A2.Request a2Req = (A2.Request) request;
            if (a2Req.isScpType01()) {
                log.info("SCP01 Type");
                log.info("request : {}", a2Req);
            } else {
                log.info("SCP02 Type");
                log.info("request : {}", a2Req);
            }

            resultMap.put(Constants.AUTH_APDU, "00A4040007A000000003101000");
            resultMap.put(Constants.PUT_APDU, "00A4040007A000000003101000");
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
