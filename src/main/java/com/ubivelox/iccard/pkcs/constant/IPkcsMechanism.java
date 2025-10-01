package com.lotson.hmc.pkcs.constant;


import com.lotson.hmc.pkcs.IaikPKCSWrapper;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.xipki.pkcs11.wrapper.PKCS11Constants;


@Getter
@AllArgsConstructor
public enum IPkcsMechanism {
    SEED_VENDOR         ("(Vendor-Specific) 0x00000000DE4369A5",    "SEED",         "SEED",         IaikPKCSWrapper.CKM_SEED_ECB,                   IaikPKCSWrapper.CKK_SEED,    16,     IaikPKCSWrapper.CKM_SEED_ECB, IaikPKCSWrapper.CKM_SEED_CBC, IaikPKCSWrapper.CKM_SEED_KEY_GEN), // 최상위 필요
    SEED                ("CKK_SEED",                                "SEED",         "SEED",         IaikPKCSWrapper.CKM_SEED_ECB,                   PKCS11Constants.CKK_SEED,    16,     IaikPKCSWrapper.CKM_SEED_ECB, IaikPKCSWrapper.CKM_SEED_CBC, IaikPKCSWrapper.CKM_SEED_KEY_GEN),
    CKK_DES             ("CKK_DES",                                 "DES",          "DES",          PKCS11Constants.CKM_DES_ECB,                    PKCS11Constants.CKK_DES,     8,      PKCS11Constants.CKM_DES_ECB,  PKCS11Constants.CKM_DES_CBC,  PKCS11Constants.CKM_DES_KEY_GEN),
    CKK_DES2            ("CKK_DES2",                                "DES2",         "DES2",         PKCS11Constants.CKM_DES3_ECB,                   PKCS11Constants.CKK_DES2,    8,      PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKM_DES3_CBC, PKCS11Constants.CKM_DES2_KEY_GEN), //DES3 랑 섞어서 씀
    CKK_DES3            ("CKK_DES3",                                "DES3",         "DES3",         PKCS11Constants.CKM_DES3_ECB,                   PKCS11Constants.CKK_DES3,    8,      PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKM_DES3_CBC, PKCS11Constants.CKM_DES3_KEY_GEN),
    CKK_AES             ("CKK_AES",                                 "AES",          "AES",          PKCS11Constants.CKM_AES_ECB,                    PKCS11Constants.CKK_AES,     16,     PKCS11Constants.CKM_AES_ECB,  PKCS11Constants.CKM_AES_CBC,  PKCS11Constants.CKM_AES_KEY_GEN),
    CKK_RSA             ("CKK_RSA",                                 "RSA",          "RSA",          PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN,      PKCS11Constants.CKK_RSA,     16,     PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN), // 사용x 예정
    CKK_RSA_PUBLIC      ("CKK_RSA_PUBLIC",                          "RSA_PUBLIC",   "RSA_PUBLIC",   PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN,      PKCS11Constants.CKK_RSA,     16,     PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN),
    CKK_RSA_PRIVATE     ("CKK_RSA_PRIVATE",                         "RSA_PRIVATE",  "RSA_PRIVATE",  PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN,      PKCS11Constants.CKK_RSA,     16,     PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_RSA_PKCS, PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);

    private final String code;
    private final String name;
    private final String alias;
    private final long mechanism;
    private final long keyType;
    private final int blockSize;
    private final long ecb;
    private final long cbc;
    private final long genMechanism;

    IPkcsMechanism(String code, String name, String alias, long mechanism, long keyType, int blockSize, long genMechanism) {
        this.code = code;
        this.name = name;
        this.alias = alias;
        this.mechanism = mechanism;
        this.keyType = keyType;
        this.blockSize = blockSize;
        this.ecb = 0;
        this.cbc = 0;
        this.genMechanism = genMechanism;
    }

    public static IPkcsMechanism findByKeyType(String code) {
        if (StringUtils.isBlank(code)) {
            throw new RuntimeException(String.format("Argument[%s] code is blank", code));
        }
        for (IPkcsMechanism pkcs : IPkcsMechanism.values()) {
            if (pkcs.getKeyType() == Long.parseLong(code)) {
                return pkcs;
            }

        }
        throw new RuntimeException(String.format("Not found Code[%s]", code));
    }


    public static IPkcsMechanism of(String code) {
        if(StringUtils.isBlank(code)) throw new RuntimeException(String.format("Argument[%s] code is blank", code));
        for(IPkcsMechanism pkcs : IPkcsMechanism.values()) {
            if(StringUtils.equals(pkcs.getCode(), code)) {
                return pkcs;
            }
            if(StringUtils.equals(pkcs.getAlias(), code)) {
                return pkcs;
            }
        }
        throw new RuntimeException(String.format("Not found Code[%s]", code));
    }

    public static CK_MECHANISM getMechanism(String attrName) {
        long mechanism = findByKeyType(attrName).getMechanism();
        CK_MECHANISM ckMechanism = new CK_MECHANISM();
        ckMechanism.mechanism = mechanism;
        return ckMechanism;
    }
}


