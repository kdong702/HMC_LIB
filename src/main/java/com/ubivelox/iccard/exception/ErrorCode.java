package com.ubivelox.iccard.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // TASK 에러
    NOT_FOUND_SLOT                      ("900005",   "NOT_FOUND_SLOT"),
    INVALID_PROTOCOL_LENGTH             ("HD300001",   "INVALID_PROTOCOL_LENGTH"),
    INVALID_KEY_LABEL                   ("HD300002",   "INVALID_KEY_LABEL"),
    NOT_USE_ALGORITHM                   ("HD300003",  "INVALID_ALGORITHM"),
    C_ENCRYPT_JCE                       ("HD300004",  "ENCRYPT_JCE ERROR"),
    C_DECRYPT_JCE                       ("HD300005",  "DECRYPT_JCE ERROR"),
    INVALID_SCP_TYPE                    ("HD300006",  "INVALID_SCP_TYPE"),
    INVALID_TAG_FLAG                    ("HD300007",  "INVALID_TAG_FLAG"),
    AUTH_FAIL                           ("HD300008",  "AUTH_FAIL"),

    // PKCS 에러
    ERR_HANDLE_ENC_DATA                 ("CS0220",   "암호화 오류입니다."),
    ERR_HSM_INIT                        ("CS0030",   "HSM 초기화에 실패하였습니다."),
    ERR_HSM_SYNC                        ("CS0033",   "HSM 동기화에 실패하였습니다."),
    ERR_HSM_FINALIZE                    ("CS0031",   "HSM 종료에 실패하였습니다."),
    ERR_NOT_EXIST_DATA                  ("CS0023",   "데이터 형식이 잘못되어 있습니다."),

    ERR_C_OPEN_SESSION                  ("HS100001",   "C_OpenSession PKCS11Exception."),
    ERR_C_GET_MECHANISM_LIST            ("HS100002",   "C_GetMechanismList PKCS11Exception."),
    ERR_C_FIND_OBJECTS_INIT             ("HS100003",   "C_FindObjectsInit PKCS11Exception."),
    ERR_C_FIND_OBJECTS                  ("HS100004",   "C_FindObjects PKCS11Exception."),
    ERR_C_FIND_OBJECTS_FINAL            ("HS100005",   "C_FindObjectsFinal PKCS11Exception."),
    ERR_C_WRAP_KEY                      ("HS100006",   "C_WrapKey PKCS11Exception."),
    ERR_C_UNWRAP_KEY                    ("HS100007",   "C_UnWrapKey PKCS11Exception."),
    ERR_C_ENCRYPT_INIT                  ("HS100008",   "C_EncryptInit PKCS11Exception."),
    ERR_C_ENCRYPT                       ("HS100009",   "C_Encrypt PKCS11Exception."),
    ERR_C_DECRYPT_INIT                  ("HS100010",   "C_DecryptInit PKCS11Exception."),
    ERR_C_DECRYPT                       ("HS100011",   "C_Decrypt PKCS11Exception."),
    ERR_C_CREATE_OBJECT                 ("HS100012",   "C_CreateObject PKCS11Exception."),
    ERR_C_GENERATE_OBJECT               ("HS100013",   "C_GenerateObject PKCS11Exception."),
    ERR_C_LOGIN                         ("HS100014",   "C_Login PKCS11Exception."),
    ERR_C_CLOSE_SESSION                 ("HS100015",   "C_CloseSession PKCS11Exception."),
    ERR_C_LOGOUT                        ("HS100016",   "C_Logout PKCS11Exception."),
    ERR_C_GET_ATTRIBUTE                 ("HS100017",   "C_GetAttribute PKCS11Exception"),
    ERR_HANDLE_CREATE_OBJ_KEY           ("HS100018",   "OutputHandle 가져오기 실패했습니다.."),
    ERR_HANDLE_DEC_DATA                 ("HS100019",   "DecHandle 가져오기 실패했습니다."),
    ERR_GET_MODULE                      ("HS100020",   "PKCS11Module 가져오기 실패했습니다."),
    ERR_GET_SLOT_LIST                   ("HS100021",   "PKCS11Module getSlotList 실패했습니다."),
    ERR_GET_SLOT_INFO                   ("HS100022",   "PKCS11Module Slot getSlotInfo PKCS11Exception."),
    ERR_MODULE_INIT                     ("HS100023",   "PKCS11Module initialize 실패했습니다."),
    ERR_C_DESTROY_OBJECT                ("HS100024",   "PKCS11Module C_DestroyObject 실패했습니다."),
    ERR_C_LOGIN_CKR_PIN_INCORRECT       ("HS100025",   "CKR_PIN_INCORRECT."),
    ERR_C_DERIVE_KEY                    ("HS100026",   "C_DERIVE_KEY PKCS11Exception."),


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
