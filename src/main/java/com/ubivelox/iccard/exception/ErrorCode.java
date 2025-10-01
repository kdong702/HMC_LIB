package com.lotson.hmc.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    OK                                  ("0",         HttpStatus.OK,                      "Ok"),

    NOT_FOUND                           ("404",       HttpStatus.NOT_FOUND,               "Requested resource is not found"),

    BAD_REQUEST                         ("10000",     HttpStatus.BAD_REQUEST,             "Bad request"),
    SPRING_BAD_REQUEST                  ("10001",     HttpStatus.BAD_REQUEST,             "Spring-detected bad request"),
    VALIDATION_ERROR                    ("10002",     HttpStatus.BAD_REQUEST,             "Validation error"),

    INTERNAL_ERROR                      ("20000",     HttpStatus.INTERNAL_SERVER_ERROR,   "Internal error"),
    SPRING_INTERNAL_ERROR               ("20001",     HttpStatus.INTERNAL_SERVER_ERROR,   "Spring-detected internal error"),
    SQL_ERROR                           ("20002",     HttpStatus.INTERNAL_SERVER_ERROR,   "SQL error"),
    FILE_UPLOAD_FAIL                    ("20003",     HttpStatus.INTERNAL_SERVER_ERROR,   "File Upload Filed"),
    EMPTY_FILE                          ("20004",     HttpStatus.INTERNAL_SERVER_ERROR,   "File is empty"),

    // TASK 에러
    NOT_FOUND_TASK                      ("900001",    HttpStatus.INTERNAL_SERVER_ERROR,   "NOT_FOUND_TASK"),
    NOT_FOUND_MODULE                    ("900002",    HttpStatus.INTERNAL_SERVER_ERROR,   "NOT_FOUND_MODULE"),
    NOT_FOUND_CLASS                     ("900003",    HttpStatus.INTERNAL_SERVER_ERROR,   "NOT_FOUND_CLASS"),
    ERROR_INSTANTIATION_TASK            ("900004",    HttpStatus.INTERNAL_SERVER_ERROR,   "ERROR_INSTANTIATION_TASK"),
    NOT_FOUND_SLOT                      ("900005",    HttpStatus.INTERNAL_SERVER_ERROR,   "NOT_FOUND_SLOT"),
    INVALID_PROTOCOL_LENGTH             ("900006",    HttpStatus.INTERNAL_SERVER_ERROR,   "INVALID_PROTOCOL_LENGTH"),
    INVALID_KEY_LIST                    ("900007",    HttpStatus.INTERNAL_SERVER_ERROR,   "INVALID_KEY_LIST"),
    INVALID_PROTOCOL                    ("900008",    HttpStatus.INTERNAL_SERVER_ERROR,   "INVALID_PROTOCOL"),
    INVALID_TASK_STEP                   ("900011",    HttpStatus.INTERNAL_SERVER_ERROR,   "INVALID_TASK_STEP"),

    // 우리은행 에러
    INVALID_EAI_SERVER                  ("900021",    HttpStatus.INTERNAL_SERVER_ERROR,   "INVALID_EAI_SERVER"),
    NOT_RECEIVE_ACK                     ("900022",    HttpStatus.INTERNAL_SERVER_ERROR,   "NOT_RECEIVE_ACK"),
    NOT_VALID_RESULT                    ("900023",    HttpStatus.INTERNAL_SERVER_ERROR,   "NOT_VALID_RESULT"),
    NOT_EXIST_DTI_DATA                  ("900024",    HttpStatus.INTERNAL_SERVER_ERROR,   "NOT_EXIST_DTI_DATA"),

    //PKCS 에러
    ERR_HANDLE_ENC_DATA                 ("CS0220",    HttpStatus.INTERNAL_SERVER_ERROR,   "암호화 오류입니다."),
    ERR_HSM_INIT                        ("CS0030",    HttpStatus.INTERNAL_SERVER_ERROR,   "HSM 초기화에 실패하였습니다."),
    ERR_HSM_SYNC                        ("CS0033",    HttpStatus.INTERNAL_SERVER_ERROR,   "HSM 동기화에 실패하였습니다."),
    ERR_HSM_FINALIZE                    ("CS0031",    HttpStatus.INTERNAL_SERVER_ERROR,   "HSM 종료에 실패하였습니다."),
    ERR_NOT_EXIST_DATA                  ("CS0023",    HttpStatus.INTERNAL_SERVER_ERROR,   "데이터 형식이 잘못되어 있습니다."),
    ERR_C_OPEN_SESSION                  ("999999",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_OpenSession PKCS11Exception."),
    ERR_C_GET_MECHANISM_LIST            ("999998",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_GetMechanismList PKCS11Exception."),
    ERR_C_FIND_OBJECTS_INIT             ("999997",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_FindObjectsInit PKCS11Exception."),
    ERR_C_FIND_OBJECTS                  ("999996",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_FindObjects PKCS11Exception."),
    ERR_C_FIND_OBJECTS_FINAL            ("999995",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_FindObjectsFinal PKCS11Exception."),
    ERR_C_WRAP_KEY                      ("999994",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_WrapKey PKCS11Exception."),
    ERR_C_UNWRAP_KEY                    ("999993",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_UnWrapKey PKCS11Exception."),
    ERR_C_ENCRYPT_INIT                  ("999992",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_EncryptInit PKCS11Exception."),
    ERR_C_ENCRYPT                       ("999991",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_Encrypt PKCS11Exception."),
    ERR_C_DECRYPT_INIT                  ("999990",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_DecryptInit PKCS11Exception."),
    ERR_C_DECRYPT                       ("999989",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_Decrypt PKCS11Exception."),
    ERR_C_CREATE_OBJECT                 ("999988",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_CreateObject PKCS11Exception."),
    ERR_C_GENERATE_OBJECT               ("999987",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_GenerateObject PKCS11Exception."),
    ERR_C_LOGIN                         ("999986",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_Login PKCS11Exception."),
    ERR_C_CLOSE_SESSION                 ("999985",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_CloseSession PKCS11Exception."),
    ERR_C_LOGOUT                        ("999984",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_Logout PKCS11Exception."),
    ERR_C_GET_ATTRIBUTE                 ("999983",    HttpStatus.INTERNAL_SERVER_ERROR,   "C_GetAttribute PKCS11Exception"),
    ERR_HANDLE_CREATE_OBJ_KEY           ("999982",    HttpStatus.INTERNAL_SERVER_ERROR,   "OutputHandle 가져오기 실패했습니다.."),
    ERR_HANDLE_DEC_DATA                 ("999981",    HttpStatus.INTERNAL_SERVER_ERROR,   "DecHandle 가져오기 실패했습니다."),
    ERR_GET_MODULE                      ("999980",    HttpStatus.INTERNAL_SERVER_ERROR,   "PKCS11Module 가져오기 실패했습니다."),
    ERR_GET_SLOT_LIST                   ("999979",    HttpStatus.INTERNAL_SERVER_ERROR,   "PKCS11Module getSlotList 실패했습니다."),
    ERR_GET_SLOT_INFO                   ("999978",    HttpStatus.INTERNAL_SERVER_ERROR,   "PKCS11Module Slot getSlotInfo PKCS11Exception."),
    ERR_MODULE_INIT                     ("999977",    HttpStatus.INTERNAL_SERVER_ERROR,   "PKCS11Module initialize 실패했습니다."),
    ERR_C_DESTROY_OBJECT                ("999976",    HttpStatus.INTERNAL_SERVER_ERROR,   "PKCS11Module C_DestroyObject 실패했습니다."),
    ERR_C_LOGIN_CKR_PIN_INCORRECT       ("999975",    HttpStatus.INTERNAL_SERVER_ERROR,   "CKR_PIN_INCORRECT."),

    ERR_INVALID_GROUP_CD                ("600001",    HttpStatus.INTERNAL_SERVER_ERROR,   "중복된 Group 코드입니다. 다른 Group 코드를 사용해주세요."),
    ERR_INVALID_TASK_CD                 ("600002",    HttpStatus.INTERNAL_SERVER_ERROR,   "중복된 Task 코드입니다. 다른 Task 코드를 사용해주세요."),
    ERR_INVALID_KEY_ROLE                ("600003",    HttpStatus.INTERNAL_SERVER_ERROR,   "중복된 Key 라벨입니다. 하나의 키에 하나의 역할만 가능합니다."),
    ERR_REGISTER_LIB_FAIL               ("600004",    HttpStatus.INTERNAL_SERVER_ERROR,   "라이브러리 등록 실패했습니다."),
    ERR_INVALID_SLOT_LABEL              ("600005",    HttpStatus.INTERNAL_SERVER_ERROR,   "없는 슬롯 라벨입니다. 슬롯 라벨을 확인해 주세요."),
    ERR_INVALID_VERSION                 ("600006",    HttpStatus.INTERNAL_SERVER_ERROR,   "중복된 VERSION 입니다. 다른 VERSION 를 사용해주세요."),
    ERR_INVALID_ROLE                    ("600007",    HttpStatus.INTERNAL_SERVER_ERROR,   "Role 선택이 잘못 되었습니다."),
    ERR_DUPLE_ROLE                      ("600008",    HttpStatus.INTERNAL_SERVER_ERROR,   "해당 Task의 Role이 이미 존재합니다. 해당 Role의 키를 삭제후 시도해주세요."),
    ERR_USER_PWD_MATCH                  ("600009",    HttpStatus.INTERNAL_SERVER_ERROR,   "비밀번호가 서로 불일치합니다."),
    ERR_DUPLE_USERID                    ("600010",    HttpStatus.INTERNAL_SERVER_ERROR,   "이미 중복된 ID가 존재합니다. 다른 아이디를 사용하시길 바랍니다."),
    ERR_SUPER_ADMIN                     ("600011",    HttpStatus.INTERNAL_SERVER_ERROR,   "해당 계정은 슈퍼 어드민 계정이라 삭제 불가합니다"),
    ERR_USER_OLD_PWD_NOT_MATCH          ("600012",    HttpStatus.INTERNAL_SERVER_ERROR,   "기존 비밀번호가 틀립니다."),
    ERR_PROFILE_JOB_HIS_INSERT          ("600013",    HttpStatus.INTERNAL_SERVER_ERROR,   "프로파일 작업 이력 등록 실패했습니다."),
    ERR_INVALID_PARAM                   ("600014",    HttpStatus.INTERNAL_SERVER_ERROR,   "해당 파라미터 값이 없습니다."),
    ERR_API                             ("600015",    HttpStatus.INTERNAL_SERVER_ERROR,   "API 통신 오류입니다."),
    ERR_NOT_MATCH_USER_ID               ("600016",    HttpStatus.INTERNAL_SERVER_ERROR,   "다른 계정의 USER_ID입니다. 변경 불가합니다."),
    ERR_NOT_PERMIT                      ("600017",    HttpStatus.INTERNAL_SERVER_ERROR,   "SUPER_ADMIN 권한으로만 가능합니다."),
    ERR_INVALID_SQL                     ("600018",    HttpStatus.INTERNAL_SERVER_ERROR,   "유효하지 않는 SQL 입니다."),
    ERR_NOT_CONTAIN_WHERE_SQL           ("600019",    HttpStatus.INTERNAL_SERVER_ERROR,   "WHERE 절이 필수입니다."),
    ERR_INVALID_LAYOUT_CD               ("600020",    HttpStatus.INTERNAL_SERVER_ERROR,   "적절하지 않은 레이아웃 ID입니다. 다른 ID를 사용해주세요."),


    // TODO: 필요한 에러 정의
    ;

    private final String code;
    private final HttpStatus httpStatus;
    private final String message;

    public static ErrorCode valueOf(HttpStatus httpStatus) {
        if (httpStatus == null) {
            throw new BusinessException("HttpStatus is null.");
        }

        return Arrays.stream(values())
                .filter(errorCode -> errorCode.getHttpStatus() == httpStatus)
                .findFirst()
                .orElseGet(() -> {
                    if (httpStatus.is4xxClientError()) {
                        return ErrorCode.BAD_REQUEST;
                    } else if (httpStatus.is5xxServerError()) {
                        return ErrorCode.INTERNAL_ERROR;
                    } else {
                        return ErrorCode.OK;
                    }
                });
    }

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
