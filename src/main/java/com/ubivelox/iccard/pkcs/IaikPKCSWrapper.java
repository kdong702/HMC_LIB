package com.lotson.hmc.pkcs;


import com.lotson.hmc.common.Constants;
import com.lotson.hmc.exception.BusinessException;
import com.lotson.hmc.exception.ErrorCode;
import com.lotson.hmc.model.Slot;
import com.lotson.hmc.pkcs.constant.IPkcsMechanism;
import com.lotson.hmc.pkcs.constant.ITemplate;

import com.lotson.hmc.util.HexUtil;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_DES_KEY_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;


@Getter
@Slf4j
public class IaikPKCSWrapper {

    public static final long CKK_VENDOR_DEFINED = 0x80000000L;
    public static final long CKK_SEED = CKK_VENDOR_DEFINED + 0x0203L;
    public static final long CKM_SEED_KEY_GEN = CKK_VENDOR_DEFINED + 0x9d0L;
    public static final long CKM_SEED_ECB = CKK_VENDOR_DEFINED + 0x9d1L;
    public static final long CKM_SEED_CBC = CKK_VENDOR_DEFINED + 0x9d2L;
    public static final long CKM_SEED_MAC = CKK_VENDOR_DEFINED + 0x9d3L;
    public static final long CKM_SEED_MAC_GENERAL = CKK_VENDOR_DEFINED + 0x9d4L;
    public static final long CKM_SEED_ECB_PAD = CKK_VENDOR_DEFINED + 0x9d5L;
    public static final long CKM_SEED_CBC_PAD = CKK_VENDOR_DEFINED + 0x9d6L;

    private PKCS11Module pkcs11;
    private PKCS11 pkcs11api;
    private final HashMap<String, Slot> slotMap = new HashMap<String, Slot>();

    public void initPKCS11(String libFile, String slotPassword, HashMap<String, Slot> copySlotMap) {
        slotMap.clear();
        try {
            pkcs11 = PKCS11Module.getInstance(libFile); // 처음 시작할때,
            pkcs11api = pkcs11.getPKCS11Module();
            pkcs11.initialize();

            initSlotMap(slotPassword, copySlotMap);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_HSM_INIT);
        }
    }

    private void initSlotMap(String slotPassword, HashMap<String, Slot> copySlotMap) throws PKCS11Exception {
        org.xipki.pkcs11.wrapper.Slot[] slots = pkcs11.getSlotList(false);

        for (int i = 0; i < slots.length; i++) {
            long slotId = slots[i].getSlotID();

            String slotDesc = (slots[i].getSlotInfo().getSlotDescription()).trim();

            String slotLabel = slots[i].getToken().getTokenInfo().getLabel();
            log.info("Slot Label: " + slotLabel + ", Slot Desc: " + slotDesc + ", ID:" + slotId);
            // TODO 제외영역 properties로 관리하기
            if (StringUtils.isEmpty(slotLabel)) {
                continue;
            }

            if (StringUtils.equals(slotLabel, "AdminToken (0000)")) {
                continue;
            }

            if (!(slotDesc == null || slotDesc.length() < 1) ) { // 기본값 제외 분기 처리 ,refresh로 들어오는경우 그냥 두기.

                log.info("신규 slotLabel: " + slotLabel + ", 기본값 비밀번호로 세팅");
                log.info("----------- TokenID: " + slots[i].getToken().getTokenID());
                log.info("----------- Token Label ID: " + slotLabel);
                log.info("----------- Token의 slot의 desc: " + slots[i].getToken().getSlot().getSlotInfo().getSlotDescription());
                log.info("----------- SLOT DESC:" + slotDesc + ", ID:" + slotId);
                slotMap.put(slotLabel, new Slot(slotLabel, slotId, slotPassword, 0, "", 0, Constants.NO));

                if (copySlotMap != null) {
                    if (copySlotMap.containsKey(slotLabel)) {
                        log.info("기존 slotLabel: " + copySlotMap.get(slotLabel) + ", 기존 slotLabel: " + slotLabel);
                        Slot existingSlot = copySlotMap.get(slotLabel);
                        String existingPassword = existingSlot.getSlotPassword();
                        long existingSessionId = existingSlot.getSessionId();
                        if (existingSessionId != 0) { // 기존에 로그인된 비밀번호가 맞는 경우
                            log.info("기존에 로그인된 비밀번호가 맞는 경우 기존 비밀번호 유지 SlotLabel: {}", slotLabel);
                            slotMap.put(slotLabel, new Slot(slotLabel, slotId, existingPassword, 0, "", 0, Constants.NO));
                        }
                    }
                }


            }
        }
    }

    public void syncPKCS11(String libFile, String slotPassword, HashMap<String, Slot> copySlotMap) {
        finalizePCKS11();
        initPKCS11(libFile, slotPassword, copySlotMap);
    }

    public void finalizePCKS11() {
        try {
            if (pkcs11 != null) { // 종료 호출
                log.info("finalizePCKS11");
                pkcs11api = pkcs11.getPKCS11Module();
                pkcs11api.finalize();
            }
        } catch (PKCS11Exception e) {
            throw new BusinessException(ErrorCode.ERR_HSM_FINALIZE);
        } catch (Throwable e) {
            throw new BusinessException(ErrorCode.ERR_HSM_FINALIZE);
        }
    }

    public long openSession(String slotLabel) {
        long slotId = slotMap.get(slotLabel).getId();
        long sessionId = 0;
        try {
            sessionId = pkcs11api.C_OpenSession(slotId, PKCS11Constants.CKF_RW_SESSION | PKCS11Constants.CKF_SERIAL_SESSION, null, null);
        } catch (PKCS11Exception e) {
            // 에러메시지 정리 불가 -> front단에서 slotLabel substring 하여 사용
            throw new BusinessException(ErrorCode.ERR_C_OPEN_SESSION ,String.format("[%s]: Slot openSession 실패하였습니다.", slotLabel));
        }
        return sessionId;
    }

    public long loginSession(String slotLabel, String password) {
        long sessionId = openSession(slotLabel);
        Slot slot = slotMap.get(slotLabel);

        try {
            pkcs11api.C_Login(sessionId, PKCS11Constants.CKU_USER, password.toCharArray(), false);
            log.info("Slot Login 성공 ={}", slotLabel);
            slot.setSessionId(sessionId);
            slot.setLastUsedTime(System.currentTimeMillis());
            slot.setSlotPassword(password);
        } catch (PKCS11Exception pe) {
            if (pe.getMessage().contains("CKR_PIN_LOCKED")) {
                log.error("PIN LOCKED 상태입니다. 한번 더 로그인 시도");
                slot.setSlotPassword(password);
                slot.setSessionId(0);
                slot.setStatus(Constants.NO);
                closeSession(sessionId);
                throw new BusinessException(ErrorCode.ERR_C_LOGIN, String.format("[%s]: Slot PIN LOCKED 상태입니다. 잠시후 다시 시도해주세요.", slotLabel));
            }
            log.error(pe.getMessage());
//            log.error(pe.getMessage(), pe);
            slot.setSessionId(0);
            slot.setStatus(Constants.NO);
            closeSession(sessionId);
            throw new BusinessException(ErrorCode.ERR_C_LOGIN, String.format("[%s]: Slot Login 실패하였습니다.", slotLabel));

        }
        return sessionId;
    }

    public void closeSession(long sessionId) {
        try {
            pkcs11api.C_CloseSession(sessionId);
        } catch (PKCS11Exception pe) {
            log.error(pe.getMessage(), pe);
            throw new BusinessException(ErrorCode.ERR_C_CLOSE_SESSION, String.format("[%s]: closeSession 실패하였습니다.", sessionId));
        }
    }

    /**
     * 임시로 틀린 비밀번호 setting 안할 경우, 1분마다 성공했던 비밀번호로 시도를 하게됨
     */
    public void logoutSession(String slotLabel, long sessionId) {
        Slot slot = slotMap.get(slotLabel);
        try {
            pkcs11api.C_Logout(sessionId);
            slot.setSessionId(0);
            slot.setStatus(Constants.NO);
            slot.setSlotPassword("0");
        } catch (PKCS11Exception pe) {
            log.error(pe.getMessage(), pe);
            throw new BusinessException(ErrorCode.ERR_C_LOGOUT, String.format("[%s]: logout Session 실패하였습니다.", sessionId));
        }
        closeSession(sessionId);
    }

    public long[] findObjects(long sessionId, CK_ATTRIBUTE template[], long ulMaxObjectCount){
        long[] keyList = new long[0];
        try {
            pkcs11api.C_FindObjectsInit(sessionId, template, false);
            keyList = pkcs11api.C_FindObjects(sessionId, ulMaxObjectCount);
            pkcs11api.C_FindObjectsFinal(sessionId);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_FIND_OBJECTS, "key 리스트 조회에 실패했습니다.");
        }
        return keyList;
    }

    public long createObject(long sessionId, CK_ATTRIBUTE[] template) {
        long key = 0;
        try {
            key = pkcs11api.C_CreateObject(sessionId, template, false);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_CREATE_OBJECT);
        }
        return key;
    }

    public long generateObject(long sessionId, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template) {
        long key = 0;
        try {
            key = pkcs11api.C_GenerateKey(sessionId, mechanism, template, false);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_GENERATE_OBJECT);
        }
        return key;
    }

    public long[] createObjectPair(long sessionId, CK_ATTRIBUTE[] publicTemplate, CK_ATTRIBUTE[] privateTemplate) {
        long[] key = new long[2];
        CK_MECHANISM ckMechanism = new CK_MECHANISM();
        ckMechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        try {
            key = pkcs11api.C_GenerateKeyPair(sessionId, ckMechanism, publicTemplate, privateTemplate, false);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_CREATE_OBJECT);
        }
        return key;
    }

    public void destroyObject(long sessionId, long ObjKey) {
        try {
            pkcs11api.C_DestroyObject(sessionId, ObjKey);
        } catch (PKCS11Exception e) {
            throw new BusinessException(ErrorCode.ERR_C_DESTROY_OBJECT);
        }
    }

    public boolean checkStatus(Slot slot) {

        long sessionId = slot.getSessionId();
        CK_ATTRIBUTE template[] = ITemplate.createTempObjTemplate();
        try {
            long keyId = createObject(sessionId, template);
            destroyObject(sessionId, keyId);
            slot.setStatus(Constants.YES);
            return true;
        } catch (Exception e) {
            log.error(e.getMessage());
            slot.setStatus(Constants.NO);
            slot.setSessionId(0);
            return false;
        }
    }

    public CK_ATTRIBUTE[] getAttribute(long sessionId, long ObjKey, CK_ATTRIBUTE[] template) {
        try {
            pkcs11api.C_GetAttributeValue(sessionId, ObjKey, template, false);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_GET_ATTRIBUTE);
        }
        return template;
    }

    public byte[] encrypt(long sessionId, CK_MECHANISM mechanism, long keyId, byte[] plainData) {
        byte[] result;
        try {
            pkcs11api.C_EncryptInit(sessionId, mechanism, keyId, false);
            result = pkcs11api.C_Encrypt(sessionId, plainData);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_ENCRYPT);
        }
        return result;
    }

    public byte[] decrypt(long sessionId, CK_MECHANISM mechanism, long keyId, byte[] encData) {
        byte[] result;
        try {
            pkcs11api.C_DecryptInit(sessionId, mechanism, keyId, false);
            result = pkcs11api.C_Decrypt(sessionId, encData);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_DECRYPT);
        }
        return result;
    }

    public byte[] wrapKey(long sessionId, CK_MECHANISM mechanism, long wrappingKeyId, long keyId) {
        byte[] wrappedKey;
        try {
            wrappedKey = pkcs11api.C_WrapKey(sessionId, mechanism, wrappingKeyId, keyId, false);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_WRAP_KEY);
        }
        return wrappedKey;
    }

    public long unwrapKey(long sessionId, CK_MECHANISM mechanism, long unwrappingKeyId, byte[] wrappedKey, CK_ATTRIBUTE[] template) {
        long keyId;
        try {
            keyId = pkcs11api.C_UnwrapKey(sessionId, mechanism, unwrappingKeyId, wrappedKey, template, false);
        } catch (PKCS11Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessException(ErrorCode.ERR_C_UNWRAP_KEY);
        }
        return keyId;
    }



    public String calKcv(long sessionId, String keyType, long keyId) {
        String kcv = "";
        CK_MECHANISM mechanism = IPkcsMechanism.getMechanism(keyType);

        byte[] plainData = new byte[16];
        byte[] encData = encrypt(sessionId, mechanism, keyId, plainData);
        try {
            kcv = HexUtil.toHexString(encData).substring(0, 6);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            log.error("calKcv 실패 Obj key 번호={}: ", keyId, e);
        }
        return kcv;
    }


}
