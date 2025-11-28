package com.ubivelox.iccard.task;

import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.IaikPKCSWrapper;
import com.ubivelox.iccard.pkcs.Slot;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.pkcs.constant.ITemplate;
import com.ubivelox.iccard.util.Base64Utils;
import com.ubivelox.iccard.util.HexUtils;
import com.ubivelox.iccard.util.PropertyReader;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;


@Slf4j
public class SubTask implements ITask {

    protected static IaikPKCSWrapper pkcs11Wrapper = new IaikPKCSWrapper();

    public void initModule() {
            CustomLog log = new CustomLog();
            String lib = PropertyReader.getProperty("pkcs11.lib");
            log.info("pkcs11 lib path : " + lib);
            String slotPassword = PropertyReader.getProperty("pkcs11.slot.password");
            slotPassword = Base64Utils.decodeEnc(slotPassword);

            pkcs11Wrapper.initPKCS11(lib, slotPassword, null);
            log.info("pkcs11 initPKCS11 success");
    }

    public void finalModule() {
        CustomLog log = new CustomLog();
        pkcs11Wrapper.finalizePCKS11();
        log.info("pkcs11 finalizePCKS11 success");
    }

    public long openSession(String slotLabel) {
        pkcs11Wrapper.checkInit();
        HashMap<String, Slot> slotMap = pkcs11Wrapper.getSlotMap();
        Slot slot = slotMap.get(slotLabel);
        if (slot == null) {
            log.error("slotLabel={} not found", slotLabel);
            throw new CasException(ErrorCode.NOT_FOUND_SLOT);
        }
        if (slot.getSessionId() == 0) { // 최초의 1번 로그인 필요
            String slotPassword = PropertyReader.getProperty("pkcs11.slot.password");
            slotPassword = Base64Utils.decodeEnc(slotPassword);

            log.debug("pkcs11 slot password : " + slotPassword);
            pkcs11Wrapper.loginSession(slotLabel, slotPassword); // 로그인한 세션은 항상 유지
        }
        return pkcs11Wrapper.openSession(slotLabel);
    }



    @Override
    public HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId) {
        return null;
    }

    public void closeSession(long sessionId) {
        pkcs11Wrapper.closeSession(sessionId);
    }

//
    protected long findKeyId(long sessionId, String keyLabel, String transId) {
        CustomLog log = new CustomLog(transId);
        if (StringUtils.isEmpty(keyLabel)) {
            log.error("findObj keyLabel is empty");
            throw new CasException(ErrorCode.INVALID_KEY_LABEL);
        }
        if(!StringUtils.equalsAnyIgnoreCase(PropertyReader.getProperty("profile"), "prod", "stage")){
            keyLabel = "TEST_" + keyLabel;
        }
        log.info("findObj sessionId={}, keyLabel={}", sessionId, keyLabel);
        CK_ATTRIBUTE[] template = ITemplate.findObjectTemplateWithLabel(keyLabel);

        long keyId = pkcs11Wrapper.findObject(sessionId, template);
        log.info("findObj keyId={}", keyId);
        return keyId;
    }

    protected SecretKeySpec createObjJce(byte[] keyValue, IPkcsMechanism pkcsMechanism) {

        String algorithm = pkcsMechanism.getAlgorithm();
        if (StringUtils.equals(algorithm, Constants.NOT_USE)) {
            throw new CasException(ErrorCode.NOT_USE_ALGORITHM);
        }
        log.debug("createObjJce keyValue[{}]: {} ,algorithm: {}", keyValue.length, HexUtils.toHexString(keyValue), algorithm);
        return new SecretKeySpec(keyValue, algorithm);
    }

    protected byte[] encryptJce(byte[] plainData, IPkcsMechanism pkcsMechanism, SecretKeySpec key, String padding) {
        Provider bc = Security.getProvider("BC");
        log.debug("plainData[{}]: {}", plainData.length, HexUtils.toHexString(plainData));
        if (bc == null) {
            log.debug("add BouncyCastleProvider");
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(pkcsMechanism.getAlgorithm());
            sb.append("/");
            String mode = pkcsMechanism.getMode();
            sb.append(mode);
            sb.append("/");
            sb.append(padding);
            String transformation = sb.toString();
            Cipher cipher = Cipher.getInstance(transformation); // Cipher 객체 인스턴스화
            if (StringUtils.equals(mode, Constants.CBC)) {
                IvParameterSpec iv = new IvParameterSpec(pkcsMechanism.getIv()); // IV 생성
                cipher.init(Cipher.ENCRYPT_MODE, key, iv); // Cipher 초기화
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key); // Cipher 초기화
            }
            return cipher.doFinal(plainData);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new CasException(ErrorCode.C_ENCRYPT_JCE);
        }
    }

    protected byte[] decryptJce(byte[] plainData, IPkcsMechanism pkcsMechanism, SecretKeySpec key, String padding) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(pkcsMechanism.getAlgorithm());
            sb.append("/");
            String mode = pkcsMechanism.getMode();
            sb.append(mode);
            sb.append("/");
            sb.append(padding);
            String transformation = sb.toString();
            Cipher cipher = Cipher.getInstance(transformation); // Cipher 객체 인스턴스화
            if (StringUtils.equals(mode, Constants.CBC)) {
                IvParameterSpec iv = new IvParameterSpec(pkcsMechanism.getIv()); // IV 생성
                cipher.init(Cipher.DECRYPT_MODE, key, iv); // Cipher 초기화
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key); // Cipher 초기화
            }
            return cipher.doFinal(plainData);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new CasException(ErrorCode.C_DECRYPT_JCE);
        }
    }

    protected byte[] calKCV(SecretKeySpec key, IPkcsMechanism pkcsMechanism) {
        byte[] result = new byte[3];
        byte[] kcvData = new byte[16];
        byte[] fullEncData = encryptJce(kcvData, pkcsMechanism, key, Constants.NoPadding);
        System.arraycopy(fullEncData, 0, result, 0, 3);
        return result;
    }

    protected byte[] encrypt(long sessionId, long encKey, byte[] plainData, IPkcsMechanism pkcsMechanism) {
        byte[] iv =  pkcsMechanism.getIv();
        return encryptDataWithIv(sessionId, encKey, plainData, pkcsMechanism, iv);
    }

    protected byte[] encryptDataWithIv(long sessionId, long encKey, byte[] plainData, IPkcsMechanism pkcsMechanism, byte[] iv) {
        CK_MECHANISM ckMechanism = IPkcsMechanism.makeMechanism(pkcsMechanism, iv);
        return pkcs11Wrapper.encrypt(sessionId, ckMechanism, encKey, plainData);
    }

    protected SecretKeySpec encAndMakeKey(long sessionId, long encKey, byte[] plainData, IPkcsMechanism pkcsMechanism) {
        byte[] bEncData = encrypt(sessionId, encKey, plainData, pkcsMechanism);
        return makeKeyHandleWithEncData(bEncData, pkcsMechanism);
    }


    protected SecretKeySpec makeKeyHandleWithEncData(byte[] bEncData, IPkcsMechanism pkcsMechanism)  {
        if (StringUtils.equals(pkcsMechanism.getParityYn(), Constants.YES)) {
            log.debug("bEncData 적용 전: {}", HexUtils.toHexString(bEncData));
            log.debug("makeOddParity 적용");
            bEncData = HexUtils.makeOddParity(bEncData);
        }
        return createObjJce(bEncData, pkcsMechanism);
    }
}
