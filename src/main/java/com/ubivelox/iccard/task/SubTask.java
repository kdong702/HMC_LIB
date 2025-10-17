package com.ubivelox.iccard.task;

import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.common.CustomLog;
import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.pkcs.IaikPKCSWrapper;
import com.ubivelox.iccard.pkcs.Slot;
import com.ubivelox.iccard.pkcs.constant.IPkcsMechanism;
import com.ubivelox.iccard.pkcs.constant.ITemplate;
import com.ubivelox.iccard.util.HexUtils;
import com.ubivelox.iccard.util.PropertyReader;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
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

    public String initModule() {
        try {
            CustomLog log = new CustomLog();
            String lib = PropertyReader.getProperty("pkcs11.lib");
            log.info("pkcs11 lib path : " + lib);
            String slotPassword = PropertyReader.getProperty("pkcs11.slot.password");
            log.info("pkcs11 slot password : " + slotPassword);

            pkcs11Wrapper.initPKCS11(lib, slotPassword, null);
            log.info("pkcs11 initPKCS11 success");
            return Constants.YES;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return Constants.NO;
        }
    }

    public String finalModule() {
        try {
            CustomLog log = new CustomLog();
            pkcs11Wrapper.finalizePCKS11();
            log.info("pkcs11 finalizePCKS11 success");
            return Constants.YES;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return Constants.NO;
        }
    }

    public long openSession(String slotLabel) {
        HashMap<String, Slot> slotMap = pkcs11Wrapper.getSlotMap();
        Slot slot = slotMap.get(slotLabel);
        if (slot == null) {
            log.error("slotLabel={} not found", slotLabel);
            throw new BusinessException(ErrorCode.NOT_FOUND_SLOT);
        }
        if (slot.getSessionId() == 0) { // 최초의 1번 로그인 필요
//            PropertyReader reader = new PropertyReader("src/main/resources/application.properties");
            String slotPassword = PropertyReader.getProperty("pkcs11.slot.password");
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
            throw new BusinessException(ErrorCode.INVALID_KEY_LABEL);
        }
        if(!StringUtils.equals(PropertyReader.getProperty("profile"), "prod")){
            keyLabel = "TEST_" + keyLabel;
        }
        log.info("findObj sessionId={}, keyLabel={}", sessionId, keyLabel);
        CK_ATTRIBUTE[] template = ITemplate.findObjectTemplateWithLabel(keyLabel);

        long keyId = pkcs11Wrapper.findObject(sessionId, template);
        log.info("findObj keyId={}", keyId);
        return keyId;
    }


//    protected byte[] encrypt(long sessionId, long encKey, Object plainData, IPkcsMechanism mechanism) {
//        byte[] bPlainData = new byte[0];
//        if (plainData instanceof String) {
//            bPlainData = HexUtils.toByteArray((String)plainData);
//        } else if (plainData instanceof byte[]) {
//            bPlainData = (byte[]) plainData;
//        } else {
//            log.error("class={}", plainData.getClass());
//            throw new LibException(LibErrorCode.INVALID_TYPE);
//        }
//
//        byte[] iv = mechanism.getIv();
//        CK_MECHANISM ckMechanism = PkcsMechanism.makeMechanism(mechanism, iv);
//        byte[] bEncData = pkcs11Wrapper.encrypt(sessionId, ckMechanism, encKey, bPlainData);
//        log.debug("encryptData bEncData: {}", HexUtils.toHexString(bEncData));
//        return bEncData;
//    }
//
//    protected byte[] decrypt(long sessionId, long decKey, Object plainData, PkcsMechanism mechanism) {
//        byte[] bPlainData = new byte[0];
//        if (plainData instanceof String) {
//            bPlainData = HexUtils.toByteArray((String)plainData);
//        } else if (plainData instanceof byte[]) {
//            bPlainData = (byte[]) plainData;
//        } else {
//            log.error("class={}", plainData.getClass());
//            throw new LibException(LibErrorCode.INVALID_TYPE);
//        }
//        byte[] iv = mechanism.getIv();
//        CK_MECHANISM ckMechanism = PkcsMechanism.makeMechanism(mechanism, iv);
//        byte[] bDecData = pkcs11Wrapper.decrypt(sessionId, ckMechanism, decKey, bPlainData);
//        log.debug("decryptData bDecData: {}", HexUtils.toHexString(bDecData));
//        return bDecData;
//    }
//
//

    protected SecretKeySpec createObjJce(byte[] keyValue, IPkcsMechanism pkcsMechanism) {

        String algorithm = pkcsMechanism.getAlgorithm();
        if (StringUtils.equals(algorithm, Constants.NOT_USE)) {
            throw new BusinessException(ErrorCode.NOT_USE_ALGORITHM);
        }
        log.info("createObjJce keyvalue[{}]: {} ,algorithm: {}", keyValue.length, HexUtils.toHexString(keyValue), algorithm);
        return new SecretKeySpec(keyValue, algorithm);
    }

    protected byte[] encryptJce(byte[] plainData, IPkcsMechanism pkcsMechanism, SecretKeySpec key, String padding) {
        Provider bc = Security.getProvider("BC");
        log.info("plainData[{}]: {}", plainData.length, HexUtils.toHexString(plainData));
        if (bc == null) {
            log.info("add BouncyCastleProvider");
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
            throw new BusinessException(ErrorCode.C_ENCRYPT_JCE);
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
            throw new BusinessException(ErrorCode.C_DECRYPT_JCE);
        }
    }

    protected byte[] calKCV(SecretKeySpec key, IPkcsMechanism pkcsMechanism) {
        byte[] result = new byte[3];
        byte[] kcvData = new byte[16];
        byte[] fullEncData = encryptJce(kcvData, pkcsMechanism, key, Constants.NoPadding);
        System.arraycopy(fullEncData, 0, result, 0, 3);
        return result;
    }
}
