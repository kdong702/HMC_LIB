package com.ubivelox.iccard.task;

import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.util.ByteUtils;
import com.ubivelox.iccard.util.HexUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.spec.SecretKeySpec;

@Slf4j
public class BxTask extends SubTask{

    protected byte[] makeXorDataWithCsn(String csn) {
        byte[] bCSN = HexUtils.toByteArray(csn);
        byte[] bXCSN = ByteUtils.xor(bCSN);
        byte[] bDKData = ByteUtils.copyArray(bCSN, bXCSN);
        log.debug("DKData: {}", HexUtils.toHexString(bDKData));
        return bDKData;
    }

    protected SecretKeySpec makeDkKey(long sessionId, String csn, long encKeyId, CustomLog log) {
        byte[] encDkData = makeXorDataWithCsn(csn);
        log.info("encDkData[{}] = {}",encDkData.length, HexUtils.toHexString(encDkData));
        return encAndMakeKey(sessionId, encKeyId, encDkData, IPkcsMechanism.SEED_VENDOR_CBC);
    }

    protected byte[] makeMac(SecretKeySpec encDkKey, String data, IPkcsMechanism iPkcsMechanism, CustomLog log) {
        byte[] bData = HexUtils.toByteArray(data);
        int blockSize = iPkcsMechanism.getBlockSize();
        byte[] padData = HexUtils.pad80(bData, blockSize);
        log.info("mac data[{}] = {}",padData.length, HexUtils.toHexString(padData));
        byte[] macData = encryptJce(padData, iPkcsMechanism, encDkKey, Constants.NoPadding);
        log.info("mac enc data[{}] = {}",macData.length, HexUtils.toHexString(macData));
        return HexUtils.findLastBlockData(macData, iPkcsMechanism.getBlockSize(), 4);
    }

    protected byte[] toBytesByLang(String input)  {
        try {
            if (input == null) return new byte[0];
            // 한글 포함 여부 체크 (유니코드 범위: 0xAC00~0xD7A3)
            boolean hasKorean = input.chars().anyMatch(c -> (c >= 0xAC00 && c <= 0xD7A3));
            String charset = hasKorean ? "KSC5601" : "US-ASCII";
            return input.getBytes(charset);
        } catch (Exception e) {
            throw new CasException(ErrorCode.ERR_NOT_VALID_CHARSET);
        }

    }
}
