package com.ubivelox.iccard.common;

public interface Constants {

    public static final String YES = "Y"; // database 컬럼 필드값에 Y,N 값 입력이 필요한 경우
    public static final String NO = "N"; // database 컬럼 필드값에 Y,N 값 입력이 필요한 경우
    public static final String APDU = "APDU";
    public static final String AUTH_APDU = "AUTH_APDU";
    public static final String PUT_APDU = "PUT_APDU";
    public static final String UPDATE_APDU = "UPDATE_APDU";
    public static final String MAC = "MAC";
    public static final String PIN = "PIN";
    public static final String ACCOUNT_NUMBER = "ACCOUNT_NUMBER";
    public static final String AMOUNT = "AMOUNT";
    public static final String SUCCESS = "00000000";

    public static final String NOT_USE = "NOT_USE";
    public static final String ECB = "ECB";
    public static final String CBC = "CBC";
    public static final String NoPadding = "NoPadding";
    public static final String PKCS5Padding = "PKCS5Padding";

    public static final String  INIT_KEY_LABEL = "CMK_INIT";
    public static final String  BANK_KEY_LABEL = "CMK_BANK";
    public static final String FCK_KEY_LABEL = "FCK_BANK";
    public static final String FCK_KEY_LABEL2 = "FCK_BANK_1601";
    public static final String FCK_KEY_LABEL_TEST = "CMK_FCK_40";
    public static final String BMK = "BMK";
}
