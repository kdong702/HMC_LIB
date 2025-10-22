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
public class CxTask extends SubTask{

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


}
