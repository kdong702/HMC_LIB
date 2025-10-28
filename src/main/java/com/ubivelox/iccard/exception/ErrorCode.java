package com.ubivelox.iccard.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // TASK 에러
    INVALID_PROTOCOL_LENGTH             ("HD300001",   "message buffer의 길이가 충분하지 않습니다."),
    INVALID_KEY_LABEL                   ("HD300002",   "키를 찾을 수 없습니다."),
    NOT_USE_ALGORITHM                   ("HD300003",  "지원하지 않는 암호화 알고리즘입니다."),
    C_ENCRYPT_JCE                       ("HD300004",  "Encrypt에 실패하였습니다."),
    C_DECRYPT_JCE                       ("HD300005",  "Decrypt에 실패하였습니다."),
    INVALID_SCP_TYPE                    ("HD300006",  "SCP version이 잘못되어 있습니다."),
    INVALID_TAG_FLAG                    ("HD300007",  "Tag 값이 잘못되어 있습니다."),
    AUTH_FAIL                           ("HD300008",  "ARQC 검증 오류"),
    INIT_FIRST                          ("HD300009",  "HSM 초기화를 먼저 진행해주세요."),
    NOT_FOUND_SLOT                      ("HD300010",  "슬롯을 찾을 수 없습니다."),
    ERR_NOT_VALID_CHARSET               ("HD300011",   "문자열 형식이 잘못되어 있습니다."),
    ERR_HSM_INIT                        ("HD300012",   "HSM 초기화에 실패하였습니다."),
    ERR_HSM_FINALIZE                    ("HD300013",   "HSM 종료에 실패하였습니다."),

    // PKCS 에러,




    ERR_C_OPEN_SESSION                  ("CS100001",   "C_OpenSession PKCS11Exception."),
    ERR_C_GET_MECHANISM_LIST            ("CS100002",   "C_GetMechanismList PKCS11Exception."),
    ERR_C_FIND_OBJECTS_INIT             ("CS100003",   "C_FindObjectsInit PKCS11Exception."),
    ERR_C_FIND_OBJECTS                  ("CS100004",   "C_FindObjects PKCS11Exception."),
    ERR_C_FIND_OBJECTS_FINAL            ("CS100005",   "C_FindObjectsFinal PKCS11Exception."),
    ERR_C_WRAP_KEY                      ("CS100006",   "C_WrapKey PKCS11Exception."),
    ERR_C_UNWRAP_KEY                    ("CS100007",   "C_UnWrapKey PKCS11Exception."),
    ERR_C_ENCRYPT_INIT                  ("CS100008",   "C_EncryptInit PKCS11Exception."),
    ERR_C_ENCRYPT                       ("CS100009",   "C_Encrypt PKCS11Exception."),
    ERR_C_DECRYPT_INIT                  ("CS100010",   "C_DecryptInit PKCS11Exception."),
    ERR_C_DECRYPT                       ("CS100011",   "C_Decrypt PKCS11Exception."),
    ERR_C_CREATE_OBJECT                 ("CS100012",   "C_CreateObject PKCS11Exception."),
    ERR_C_GENERATE_OBJECT               ("CS100013",   "C_GenerateObject PKCS11Exception."),
    ERR_C_LOGIN                         ("CS100014",   "C_Login PKCS11Exception."),
    ERR_C_CLOSE_SESSION                 ("CS100015",   "C_CloseSession PKCS11Exception."),
    ERR_C_LOGOUT                        ("CS100016",   "C_Logout PKCS11Exception."),
    ERR_C_GET_ATTRIBUTE                 ("CS100017",   "C_GetAttribute PKCS11Exception."),
    ERR_GET_SLOT_LIST                   ("CS100018",   "C_GetSlotList PKCS11Exception."),
    ERR_GET_SLOT_INFO                   ("CS100019",   "C_GetSlotInfo PKCS11Exception."),
    ERR_C_DESTROY_OBJECT                ("CS100020",   "C_DestroyObject PKCS11Exception."),
    ERR_C_DERIVE_KEY                    ("CS100021",   "C_Derive_Object PKCS11Exception."),
    ERR_C_LOGIN_CKR_PIN_INCORRECT       ("CS100022",   "CKR_PIN_INCORRECT."),


    ;





    private final String code;
    private final String message;



    public String getMessage(Throwable e) {
        return this.getMessage(this.getMessage() + " - " + e.getMessage());
    }

    public String getMessage(String message) {
        return message;
    }

    @Override
    public String toString() {
        return String.format("%s (%d)", this.name(), this.getCode());
    }

}
