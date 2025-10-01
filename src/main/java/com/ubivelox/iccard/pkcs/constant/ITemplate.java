package com.ubivelox.iccard.pkcs.constant;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.ubivelox.iccard.exception.BusinessException;
import com.ubivelox.iccard.util.HexUtil;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import lombok.extern.slf4j.Slf4j;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import java.util.HashMap;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

@Slf4j
public class ITemplate {

    public static final ObjectMapper mapper = new ObjectMapper();

    public static final CK_ATTRIBUTE[] createTempObjTemplate() {
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[7];
        byte[] outBuf = HexUtil.toByteArray("0000000000000000");
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_CLASS;
        template[0].pValue = PKCS11Constants.CKO_SECRET_KEY;

        template[1] = new CK_ATTRIBUTE();
        template[1].type = PKCS11Constants.CKA_KEY_TYPE;
        template[1].pValue = PKCS11Constants.CKK_GENERIC_SECRET;

        template[2] = new CK_ATTRIBUTE();
        template[2].type = PKCS11Constants.CKA_LABEL;
        template[2].pValue = "ham temp key".toCharArray();

        template[3] = new CK_ATTRIBUTE();
        template[3].type = PKCS11Constants.CKA_TOKEN;
        template[3].pValue = false;

        template[4] = new CK_ATTRIBUTE();
        template[4].type = PKCS11Constants.CKA_DERIVE;
        template[4].pValue = true;

        template[5] = new CK_ATTRIBUTE();
        template[5].type = PKCS11Constants.CKA_VALUE;
        template[5].pValue = outBuf;

        template[6] = new CK_ATTRIBUTE();
        template[6].type = PKCS11Constants.CKA_VALUE_LEN;
        template[6].pValue = 8;

        return template;
    }

    public static final CK_ATTRIBUTE[] deriveKeyTemplate(long keyType) {
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[7];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = CKA_CLASS;
        template[0].pValue = CKO_SECRET_KEY;

        template[1] = new CK_ATTRIBUTE();
        template[1].type = CKA_KEY_TYPE;
        template[1].pValue = keyType;

        template[2] = new CK_ATTRIBUTE();
        template[2].type = CKA_LABEL;
        template[2].pValue = "ham temp key".toCharArray();

        template[3] = new CK_ATTRIBUTE();
        template[3].type = CKA_TOKEN;
        template[3].pValue = false;

        template[4] = new CK_ATTRIBUTE();
        template[4].type = CKA_DERIVE;
        template[4].pValue = true;

        template[5] = new CK_ATTRIBUTE();
        template[5].type = CKA_ENCRYPT;
        template[5].pValue = true;

        template[6] = new CK_ATTRIBUTE();
        template[6].type = CKA_DECRYPT;
        template[6].pValue = true;

        return template;
    }

    public static CK_ATTRIBUTE[] findObjectTemplateWithLabel(String keyLabel) {
        CK_ATTRIBUTE template[] = new CK_ATTRIBUTE[2];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_CLASS;
        template[0].pValue = PKCS11Constants.CKO_SECRET_KEY;

        template[1] = new CK_ATTRIBUTE();
        template[1].type = PKCS11Constants.CKA_LABEL;
        template[1].pValue = keyLabel.toCharArray();

        return template;
    }



    public static final CK_ATTRIBUTE[] getListTemplate() {
        return makeGetAttrList(CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID);
    }

    public static final CK_ATTRIBUTE[] getCertiListTemplate() {
        return makeGetAttrList(CKA_CLASS,  CKA_LABEL , CKA_APPLICATION);
    }

    public static final CK_ATTRIBUTE[] getCertificateTemplate() {
        return makeGetAttrList(CKA_LABEL,  CKA_APPLICATION , CKA_VALUE);
    }

    public static final CK_ATTRIBUTE[] checkTypeTemplate() {
        return makeGetAttrList(CKA_CLASS);
    }

    public static final CK_ATTRIBUTE[] isSensitiveTemplate() {
        return makeGetAttrList(CKA_SENSITIVE);
    }

    public static final CK_ATTRIBUTE[] keyTypeTemplate() {
        return makeGetAttrList(CKA_KEY_TYPE);
    }

    public static final CK_ATTRIBUTE[] getAttrTemplate() {
        return makeGetAttrList(CKA_PRIVATE,  CKA_SIGN , CKA_MODIFIABLE, CKA_VERIFY, CKA_DERIVE, CKA_WRAP, CKA_UNWRAP, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_DECRYPT);
    }

    public static final CK_ATTRIBUTE[] getRSADefaultTemplate() {
        return makeGetAttrList(CKA_KEY_TYPE, CKA_LABEL, CKA_ID, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_MODULUS_BITS);
    }

    public static final CK_ATTRIBUTE[] getRSATemplate() {
        return makeGetAttrList(CKA_CLASS, CKA_MODULUS_BITS, CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT, CKA_PRIVATE_EXPONENT);
    }

    public static final CK_ATTRIBUTE[] getPublicAttrTemplate() {
        return makeGetAttrList(CKA_PRIVATE,  CKA_MODIFIABLE , CKA_VERIFY, CKA_DERIVE, CKA_WRAP, CKA_ENCRYPT);
    }

    public static final CK_ATTRIBUTE[] exportTemplate() {
        return makeGetAttrList(CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN, CKA_MODIFIABLE,
                CKA_VERIFY, CKA_DERIVE, CKA_WRAP, CKA_UNWRAP, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_DECRYPT);
    }

//    public static final HashMap<String, String> parseAttrToHashMap(CK_ATTRIBUTE[] attrArray) {
//        HashMap<String, String> resultMap = new HashMap<String, String>();
//
//        try {
//            for (int i = 0; i < attrArray.length; i++) {
//                if (attrArray[i] == null) {
//                    continue;
//                }
//
//                String code = PKCS11Constants.ckaCodeToName(attrArray[i].type);
//                String value = "";
//
//                int parseNo = IPkcsAttribute.of(code).getParseNo();
//                if (parseNo == 1) {
//                    value = mapper.writeValueAsString(HexUtil.convertAsciiToChar((byte[]) attrArray[i].pValue)).replaceAll("\"", "");
//                } else if (parseNo == 2) {
//                    value = mapper.writeValueAsString(attrArray[i].pValue).replaceAll("\"", "");
//                } else if (parseNo == 3) {
//                    value = mapper.writeValueAsString(HexUtil.toHexString((byte[]) attrArray[i].pValue)).replaceAll("\"", "");
//                } else {
//                    value = String.valueOf(attrArray[i].pValue);
//                }
////
//                resultMap.put(code, value);
//            }
//
//        } catch (JsonProcessingException e) {
//            log.error(e.getMessage(), e);
//            throw new BusinessException("Attribute parsing 실패했습니다.");
//        }
//
//        return resultMap;
//    }

    private static CK_ATTRIBUTE[] makeGetAttrList(long ... type) {
        int size = type.length;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[size];
        for (int i = 0; i < size; i++) {
            template[i] = new CK_ATTRIBUTE();
            template[i].type = type[i];
        }
        return template;
    }

    public static void makeCKAttribute(int idx, CK_ATTRIBUTE[] attr, long type, Object value) {
        attr[idx] = new CK_ATTRIBUTE();
        attr[idx].type = type;
        attr[idx].pValue = value;
    }
}
