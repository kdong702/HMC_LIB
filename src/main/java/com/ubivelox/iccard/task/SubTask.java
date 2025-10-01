package com.lotson.cas.task;

import com.lotson.cas.common.LibConstants;
import com.lotson.cas.exception.LibErrorCode;
import com.lotson.cas.exception.LibException;
import com.lotson.cas.pkcs.PKCSWrapper;
import com.lotson.cas.pkcs.constant.PkcsMechanism;
import com.lotson.cas.pkcs.constant.Template;
import com.lotson.cas.utils.HexUtils;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;


@Slf4j
public class SubTask {

    protected static PKCSWrapper pkcs11Wrapper = new PKCSWrapper();

    protected void initModule(String path) {
        pkcs11Wrapper.initPKCS11(path);
    }

    protected <T> T findInitParam(String name, Map<String, Object> initParams) {
        if (initParams.get(name) == null) {
            log.error("initParam 오류 찾는값={}", name);
            throw new LibException(LibErrorCode.INVALID_PARAM);
        }
        return (T) initParams.get(name);
    }




    protected long createObj(long sessionId, long keyType, Object value) {
        String val = "";
        if (value instanceof String) {
            val = (String) value;
        } else if (value instanceof byte[]) {
            val =  HexUtils.toHexString((byte[]) value);
        } else {
            throw new LibException(LibErrorCode.INVALID_TYPE);
        }
        CK_ATTRIBUTE[] template = Template.createObjTemplate(keyType, val);
        return pkcs11Wrapper.createObject(sessionId, template);
    }

    protected long findObj(long sessionId, String keyLabel) {
        CK_ATTRIBUTE[] template = Template.findObjectTemplateWithLabel(keyLabel);
        return pkcs11Wrapper.findObject(sessionId, template);
    }

    protected byte[] encrypt(long sessionId, long encKey, Object plainData, PkcsMechanism mechanism) {
        byte[] bPlainData = new byte[0];
        if (plainData instanceof String) {
            bPlainData = HexUtils.toByteArray((String)plainData);
        } else if (plainData instanceof byte[]) {
            bPlainData = (byte[]) plainData;
        } else {
            log.error("class={}", plainData.getClass());
            throw new LibException(LibErrorCode.INVALID_TYPE);
        }

        byte[] iv = mechanism.getIv();
        CK_MECHANISM ckMechanism = PkcsMechanism.makeMechanism(mechanism, iv);
        byte[] bEncData = pkcs11Wrapper.encrypt(sessionId, ckMechanism, encKey, bPlainData);
        log.debug("encryptData bEncData: {}", HexUtils.toHexString(bEncData));
        return bEncData;
    }

    protected byte[] decrypt(long sessionId, long decKey, Object plainData, PkcsMechanism mechanism) {
        byte[] bPlainData = new byte[0];
        if (plainData instanceof String) {
            bPlainData = HexUtils.toByteArray((String)plainData);
        } else if (plainData instanceof byte[]) {
            bPlainData = (byte[]) plainData;
        } else {
            log.error("class={}", plainData.getClass());
            throw new LibException(LibErrorCode.INVALID_TYPE);
        }
        byte[] iv = mechanism.getIv();
        CK_MECHANISM ckMechanism = PkcsMechanism.makeMechanism(mechanism, iv);
        byte[] bDecData = pkcs11Wrapper.decrypt(sessionId, ckMechanism, decKey, bPlainData);
        log.debug("decryptData bDecData: {}", HexUtils.toHexString(bDecData));
        return bDecData;
    }

    protected SecretKeySpec createObjJce(byte[] keyValue, PkcsMechanism pkcsMechanism) {

        String algorithm = pkcsMechanism.getAlgorithm();
        if (StringUtils.equals(algorithm, LibConstants.NOT_USE)) {
            throw new LibException(LibErrorCode.NOT_USE_ALGORITHM);
        }
        return new SecretKeySpec(keyValue, algorithm);
    }

    protected byte[] encryptJce(byte[] plainData, PkcsMechanism pkcsMechanism, SecretKeySpec key, String padding) {
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
            if (StringUtils.equals(mode, LibConstants.CBC)) {
                IvParameterSpec iv = new IvParameterSpec(pkcsMechanism.getIv()); // IV 생성
                cipher.init(Cipher.ENCRYPT_MODE, key, iv); // Cipher 초기화
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key); // Cipher 초기화
            }
            return cipher.doFinal(plainData);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new LibException(LibErrorCode.C_ENCRYPT);
        }
    }

    protected byte[] decryptJce(byte[] plainData, PkcsMechanism pkcsMechanism, SecretKeySpec key, String padding) {
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
            if (StringUtils.equals(mode, LibConstants.CBC)) {
                IvParameterSpec iv = new IvParameterSpec(pkcsMechanism.getIv()); // IV 생성
                cipher.init(Cipher.DECRYPT_MODE, key, iv); // Cipher 초기화
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key); // Cipher 초기화
            }
            return cipher.doFinal(plainData);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new LibException(LibErrorCode.C_ENCRYPT);
        }
    }

}
