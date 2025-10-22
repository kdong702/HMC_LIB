package com.ubivelox.iccard.task;

import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.util.ByteUtils;
import com.ubivelox.iccard.util.HexUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.spec.SecretKeySpec;

@Slf4j
public class AxTask extends SubTask{

    protected byte[] F001 = {(byte) 0xF0, (byte) 0x01};
    protected byte[] endF001Tag = {(byte) 0x0F, (byte) 0x01};
    protected byte[] F002 = {(byte) 0xF0, (byte) 0x02};
    protected byte[] endF002Tag = {(byte) 0x0F, (byte) 0x02};
    protected byte[] F003 = {(byte) 0xF0, (byte) 0x03};
    protected byte[] endF003Tag = {(byte) 0x0F, (byte) 0x03};
    protected byte[] S001 = {(byte) 0x01, (byte) 0x82};
    protected byte[] S002 = {(byte) 0x01, (byte) 0x01};
    protected byte[] S003 = {(byte) 0x01, (byte) 0x81};

    protected byte[] makeDkDataWithTag(String kdd, int tagFlag) throws BusinessException {
        byte[] startTag;
        byte[] endTag;
        if (tagFlag == 1) {
            startTag = F001;
            endTag = endF001Tag;
        } else if (tagFlag == 2) {
            startTag = F002;
            endTag = endF002Tag;
        } else if (tagFlag == 3) {
            startTag = F003;
            endTag = endF003Tag;
        } else {
            throw new BusinessException(ErrorCode.INVALID_TAG_FLAG);
        }

        byte[] bKdd = HexUtils.toByteArray(kdd);
        byte[] bDKData = new byte[16];
        System.arraycopy(bKdd, 0, bDKData, 0, 2);
        System.arraycopy(bKdd, 4, bDKData, 2, 4);
        System.arraycopy(startTag, 0, bDKData, 6, 2);
        System.arraycopy(bKdd, 0, bDKData, 8, 2);
        System.arraycopy(bKdd, 4, bDKData, 10, 4);
        System.arraycopy(endTag, 0, bDKData, 14, 2);
        log.info("DKData: {}", HexUtils.toHexString(bDKData));

        return bDKData;
    }

    protected byte[] makeSkDataWithTag(String sc, int tagFlag) throws BusinessException {
        byte[] sTag;

        if (tagFlag == 1) {
            sTag = S001;
        } else if (tagFlag == 2) {
            sTag = S002;
        } else if (tagFlag == 3) {
            sTag = S003;
        } else {
            throw new BusinessException(ErrorCode.INVALID_TAG_FLAG);
        }

        byte[] bSc = HexUtils.toByteArray(sc);
        log.info("bSc: {}", HexUtils.toHexString(bSc));
        byte[] skData = new byte[16];
        System.arraycopy(sTag, 0, skData, 0, 2);
        System.arraycopy(bSc, 0, skData, 2, 2);
        byte[] sk24Data = ByteUtils.copyArray(skData, skData, 16, 8);
        log.info("sk24Data[{}] = {}", sk24Data.length, HexUtils.toHexString(sk24Data));
        return sk24Data;
    }

    protected byte[] makeSkDataWithCrnHrn(String crn, String hrn) {
        byte[] bCRN = HexUtils.toByteArray(crn);
        byte[] bHRN = HexUtils.toByteArray(hrn);
        byte[] skData = new byte[16];
        System.arraycopy(bCRN, 4, skData, 0, 4);
        System.arraycopy(bHRN, 0, skData, 4, 4);
        System.arraycopy(bCRN, 0, skData, 8, 4);
        System.arraycopy(bHRN, 4, skData, 12, 4);
        log.debug("skData: {}", HexUtils.toHexString(skData));
        byte[] sk24Data = ByteUtils.copyArray(skData, skData, 16, 8);
        log.info("skData[{}] = {}", skData.length, HexUtils.toHexString(skData));
        return sk24Data;
    }

    protected byte[] makeCcDataWithPad(String crn, String hrn) {
        byte[] bCardDerivationData = ByteUtils.copyToByteArrayWithPad(crn, hrn, 8, 8, 24);
        log.info("bCardDerivationData: {}", HexUtils.toHexString(bCardDerivationData));

        return bCardDerivationData;
    }

    protected byte[] makeCcMac(String trn, String crn, CustomLog log, SecretKeySpec encSkKey) {
        byte[] cc = makeCcData(trn, crn, log, encSkKey);
        log.info("cc = {}", HexUtils.toHexString(cc));
        return HexUtils.findLastBlockData(cc, IPkcsMechanism.DES3_CBC.getBlockSize(), 8);
    }

    protected byte[] makeCcData(String hrn, String crn, CustomLog log, SecretKeySpec encSkKey) {
        byte[] cc1Data = makeCcDataWithPad(hrn, crn);
        log.info("ccData[{}] = {}",cc1Data.length, HexUtils.toHexString(cc1Data));
        return encryptJce(cc1Data, IPkcsMechanism.DES3_CBC, encSkKey, Constants.NoPadding);
    }

    protected SecretKeySpec makeSessionKey(byte[] skData, SecretKeySpec encDkKey, IPkcsMechanism mechanism, CustomLog log) {
        byte[] encSkData = encryptJce(skData, mechanism, encDkKey, Constants.NoPadding);
        log.info("encSkData[{}] = {}", encSkData.length, HexUtils.toHexString(encSkData));
        // TODO Chiper 는 DDES 가 없으므로 3DES 로 처리 후 가공 필요
        byte[] encSk16Data = ByteUtils.cutByteArray(encSkData, 0, 16);
        byte[] encSk24Data = ByteUtils.copyArray(encSk16Data, encSk16Data, 16, 8);
        return createObjJce(encSk24Data, mechanism);
    }

    protected SecretKeySpec makeDkKey(long sessionId, String kdd, long encKeyId, CustomLog log, int tagFlag) {
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
}
