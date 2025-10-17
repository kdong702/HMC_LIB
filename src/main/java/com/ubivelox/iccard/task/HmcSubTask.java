package com.ubivelox.iccard.task;

import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.util.ByteUtils;
import com.ubivelox.iccard.util.HexUtils;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.spec.SecretKeySpec;

@Slf4j
public class HmcSubTask extends SubTask {
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

    protected byte[] makeXorDataWithCsn(String csn) {
        byte[] bCSN = HexUtils.toByteArray(csn);
        byte[] bXCSN = ByteUtils.xor(bCSN);
        byte[] bDKData = ByteUtils.copyArray(bCSN, bXCSN);
        log.debug("DKData: {}", HexUtils.toHexString(bDKData));
        return bDKData;
    }

    protected SecretKeySpec encAndMakeKey(long sessionId, long encKey, byte[] plainData, IPkcsMechanism pkcsMechanism) {
        byte[] bEncData = encrypt(sessionId, encKey, plainData, pkcsMechanism);
        return makeKeyHandleWithEncData(bEncData, pkcsMechanism);
    }


    protected SecretKeySpec makeKeyHandleWithEncData(byte[] bEncData, IPkcsMechanism pkcsMechanism)  {
        if (StringUtils.equals(pkcsMechanism.getParityYn(), Constants.YES)) {
            log.info("bEncData 적용 전: {}", HexUtils.toHexString(bEncData));
            log.info("makeOddParity 적용");
            bEncData = HexUtils.makeOddParity(bEncData);
        }
        return createObjJce(bEncData, pkcsMechanism);
    }

    protected byte[] encrypt(long sessionId, long encKey, byte[] plainData, IPkcsMechanism pkcsMechanism) {
        byte[] iv =  pkcsMechanism.getIv();
        return encryptDataWithIv(sessionId, encKey, plainData, pkcsMechanism, iv);
    }

    protected byte[] encryptDataWithIv(long sessionId, long encKey, byte[] plainData, IPkcsMechanism pkcsMechanism, byte[] iv) {
        CK_MECHANISM ckMechanism = IPkcsMechanism.makeMechanism(pkcsMechanism, iv);
        byte[] bEncData = pkcs11Wrapper.encrypt(sessionId, ckMechanism, encKey, plainData);
        log.info("encryptData bEncData: {}", HexUtils.toHexString(bEncData));
        return bEncData;
    }

    protected byte[] makeCcDataWithPad(String crn, String hrn) {
        byte[] bCardDerivationData = ByteUtils.copyToByteArrayWithPad(crn, hrn, 8, 8, 24);
        log.info("bCardDerivationData: {}", HexUtils.toHexString(bCardDerivationData));

        return bCardDerivationData;
    }

}
