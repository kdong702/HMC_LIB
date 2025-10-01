package com.ubivelox.iccard.pkcs.constant;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

@Getter
public enum IPkcsAttribute {

    CKA_CLASS          		  ("CKA_CLASS",				"CLASS",				PKCS11Constants.CKA_CLASS,			    "Class",                0),
    CKA_KEY_TYPE              ("CKA_KEY_TYPE",			"KEYTYPE",				PKCS11Constants.CKA_KEY_TYPE,			"KeyType",              0),
    CKA_TOKEN		          ("CKA_TOKEN",				"TOKEN",                PKCS11Constants.CKA_TOKEN,			    "Token",                0),
    CKA_WRAP                  ("CKA_WRAP",				"WRAP",                 PKCS11Constants.CKA_WRAP,				"Wrap",                 0),
    CKA_UNWRAP                ("CKA_UNWRAP",			"UNWRAP",               PKCS11Constants.CKA_UNWRAP,			    "Unwrap",               0),
    CKA_VALUE                 ("CKA_VALUE",				"VALUE",                PKCS11Constants.CKA_VALUE,			    "Value",                3),
    CKA_PRIVATE               ("CKA_PRIVATE",			"PRIVATE",              PKCS11Constants.CKA_PRIVATE,			"Private",              0),
    CKA_SIGN                  ("CKA_SIGN",				"SIGN",                 PKCS11Constants.CKA_SIGN,				"Sign",                 0),
    CKA_MODIFIABLE            ("CKA_MODIFIABLE",		"MODIFIABLE",           PKCS11Constants.CKA_MODIFIABLE,         "Modifiable",           0),
    CKA_VERIFY                ("CKA_VERIFY",			"VERIFY",             	PKCS11Constants.CKA_VERIFY,			    "Verify",               0),
    CKA_DERIVE                ("CKA_DERIVE",			"DERIVE",               PKCS11Constants.CKA_DERIVE,			    "Derive",               0),
    CKA_EXTRACTABLE           ("CKA_EXTRACTABLE",		"EXTRACTABLE",          PKCS11Constants.CKA_EXTRACTABLE,		"Extractable",          0),
    CKA_SENSITIVE             ("CKA_SENSITIVE",			"SENSITIVE",            PKCS11Constants.CKA_SENSITIVE,		    "Sensitive",            0),
    CKA_MECHANISM_TYPE        ("CKA_MECHANISM_TYPE",	"MECHANISM_TYPE",       PKCS11Constants.CKA_MECHANISM_TYPE, 	"MechanismType",        0),
    CKA_START_DATE            ("CKA_START_DATE",		"START_DATE",           PKCS11Constants.CKA_START_DATE,		    "StartDate",            0),
    CKA_END_DATE              ("CKA_END_DATE",			"END_DATE",             PKCS11Constants.CKA_END_DATE,			"EndDate",              0),
    CKA_LABEL                 ("CKA_LABEL",				"LABEL",                PKCS11Constants.CKA_LABEL,			    "Label",                2),
    CKA_LOCAL                 ("CKA_LOCAL", 			"LOCAL",                PKCS11Constants.CKA_LOCAL,			    "Local",                0),
    CKA_ENCRYPT               ("CKA_ENCRYPT",			"ENCRYPT",              PKCS11Constants.CKA_ENCRYPT,			"Encrypt",              0),
    CKA_DECRYPT               ("CKA_DECRYPT",			"DECRYPT",              PKCS11Constants.CKA_DECRYPT,			"Decrypt",              0),
    CKA_ID      	          ("CKA_ID",				"ID",                   PKCS11Constants.CKA_ID,				    "Id",                   1),
    CKA_MODULUS_BITS          ("CKA_MODULUS_BITS",		"MODULUS_BITS",         PKCS11Constants.CKA_MODULUS_BITS,		"ModulusBit",           0),
    CKA_MODULUS               ("CKA_MODULUS",			"MODULUS",              PKCS11Constants.CKA_MODULUS,			"Modulus",              3),
    CKA_PRIVATE_EXPONENT      ("CKA_PRIVATE_EXPONENT", 	"PRIVATE_EXPONENT",     PKCS11Constants.CKA_PRIVATE_EXPONENT,	"PrivateExponent",      3),
    CKA_PRIME_1               ("CKA_PRIME_1",			"PRIME_1",              PKCS11Constants.CKA_PRIME_1,			"Prime1",               3),
    CKA_PRIME_2               ("CKA_PRIME_2",			"PRIME_2",              PKCS11Constants.CKA_PRIME_2,			"Prime2",               3),
    CKA_EXPONENT_1            ("CKA_EXPONENT_1",		"EXPONENT_1",           PKCS11Constants.CKA_EXPONENT_1,		    "Exponent1",            3),
    CKA_EXPONENT_2            ("CKA_EXPONENT_2",		"EXPONENT_2",           PKCS11Constants.CKA_EXPONENT_2,		    "Exponent2",            3),
    CKA_COEFFICIENT           ("CKA_COEFFICIENT",		"COEFFICIENT",          PKCS11Constants.CKA_COEFFICIENT,		"Coefficient",          3),
    CKA_PUBLIC_EXPONENT       ("CKA_PUBLIC_EXPONENT",   "PUBLIC_EXPONENT",      PKCS11Constants.CKA_PUBLIC_EXPONENT,	"PublciExponent",       3),
    CKA_APPLICATION		      ("CKA_APPLICATION",   	"APPLICATION",          PKCS11Constants.CKA_APPLICATION,		"Application",          2),

    ;

    private final String attrCode;
    private final String attrName;
    private final long attribute;
    private final String alias;
    private final int parseNo;


    IPkcsAttribute(String attrCode, String attrName,  long attribute, String alias, int parseNo) {
        this.attrCode = attrCode;
        this.attrName = attrName;
        this.attribute = attribute;
        this.alias = alias;
        this.parseNo = parseNo;
    }

    public static IPkcsAttribute of(String attrName) {
        if(StringUtils.isBlank(attrName)) throw new RuntimeException(String.format("Argument[%s] attrName is blank", attrName));
        for(IPkcsAttribute pkcs : IPkcsAttribute.values()) {
            if(StringUtils.equals(pkcs.getAttrName(), attrName)) {
                return pkcs;
            }
            if(StringUtils.equals(pkcs.getAttrCode(), attrName)) {
                return pkcs;
            }
            if(StringUtils.equals(pkcs.getAlias(), attrName)) {
                return pkcs;
            }
        }
        throw new RuntimeException(String.format("Not found attrName[%s]", attrName));
    }


}
