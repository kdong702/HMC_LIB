package com.ubivelox.iccard.pkcs.constant;


import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.pkcs.IaikPKCSWrapper;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.xipki.pkcs11.wrapper.PKCS11Constants;


@Getter
@AllArgsConstructor
public enum IPkcsMechanism {
    SEED_VENDOR_ECB     ("SEED_VENDOR_ECB",  "SEED_ECB",         IaikPKCSWrapper.CKM_SEED_ECB,  IaikPKCSWrapper.CKK_SEED,    16,    null,           Constants.NO, Constants.NOT_USE,    Constants.ECB), // 최상위 필요
    SEED_VENDOR_CBC     ("SEED_VENDOR_CBC",  "SEED_CBC",         IaikPKCSWrapper.CKM_SEED_CBC,  IaikPKCSWrapper.CKK_SEED,    16,     new byte[16],     Constants.NO, Constants.NOT_USE,     Constants.CBC), // 최상위 필요
    SEED_ECB            ("SEED_ECB",         "SEED_ECB",         PKCS11Constants.CKM_SEED_ECB,  PKCS11Constants.CKK_SEED,    16,     null,          Constants.NO, Constants.NOT_USE,    Constants.ECB), // 최상위 필요
    SEED_CBC            ("SEED_CBC",         "SEED_CBC",         PKCS11Constants.CKM_SEED_CBC,  PKCS11Constants.CKK_SEED,    16,     new byte[16],     Constants.NO, Constants.NOT_USE,     Constants.CBC), // 최상위 필요
    DES_ECB             ("DES_ECB",          "DES_ECB",          PKCS11Constants.CKM_DES_ECB,    PKCS11Constants.CKK_DES,    8,     null,          Constants.YES, "DES",        Constants.ECB),
    DES_CBC             ("DES_CBC",          "DES_CBC",          PKCS11Constants.CKM_DES_CBC,    PKCS11Constants.CKK_DES,    8,     new byte[8],      Constants.YES, "DES",        Constants.CBC),
    DES2_ECB            ("DES2_ECB",         "DES2_ECB",         PKCS11Constants.CKM_DES_ECB,    PKCS11Constants.CKK_DES2,   8,     null,          Constants.YES, Constants.NOT_USE,    Constants.ECB),
    // oddParity 적용하면 안됨 (ChiperKey 용)
    DES2_DES3_ECB       ("DES3_DES2_ECB",    "DES3_DES_2_ECB",   PKCS11Constants.CKM_DES3_ECB,   PKCS11Constants.CKK_DES2,   8,     null,          Constants.NO, "DESede",    Constants.ECB),
    DES3_ECB            ("DES3_ECB",         "DES3_ECB",         PKCS11Constants.CKM_DES3_ECB,   PKCS11Constants.CKK_DES3,   8,     null,          Constants.YES, "DESede",    Constants.ECB),
    DES3_CBC            ("DES3_CBC",         "DES3_CBC",         PKCS11Constants.CKM_DES3_CBC,   PKCS11Constants.CKK_DES3,   8,     new byte[8],      Constants.YES, "DESede",    Constants.CBC),
    AES_ECB             ("AES_ECB",          "AES_ECB",          PKCS11Constants.CKM_AES_ECB,    PKCS11Constants.CKK_AES,    8,     null,          Constants.NO,  "AES",       Constants.ECB),
    AES_CBC             ("AES_CBC",          "AES_CBC",          PKCS11Constants.CKM_AES_CBC,    PKCS11Constants.CKK_AES,    8,     new byte[8],      Constants.NO,  "AES",       Constants.CBC),

    ;

    private final String code;
    private final String name;
    private final long mechanism;
    private final long keyType;
    private final int blockSize;
    private final byte[] iv;
    private final String parityYn;
    private final String algorithm;
    private final String mode;

    public static CK_MECHANISM makeMechanism(IPkcsMechanism IPkcsMechanism, byte[] iv) {
        CK_MECHANISM mechanism = new CK_MECHANISM();
        mechanism.mechanism = IPkcsMechanism.getMechanism();
        if (iv != null) {
            mechanism.pParameter = iv;
        }
        return mechanism;
    }
}


