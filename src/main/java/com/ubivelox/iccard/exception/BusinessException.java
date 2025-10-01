package com.lotson.hmc.exception;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final ErrorCode errorCode;

    public BusinessException() {
        super(ErrorCode.INTERNAL_ERROR.getMessage());
        this.errorCode = ErrorCode.INTERNAL_ERROR;
    }

    public BusinessException(String message) {
        super(ErrorCode.INTERNAL_ERROR.getMessage(message));
        this.errorCode = ErrorCode.INTERNAL_ERROR;
    }

    public BusinessException(String message, Throwable cause) {
        super(ErrorCode.INTERNAL_ERROR.getMessage(message), cause);
        this.errorCode = ErrorCode.INTERNAL_ERROR;
    }

    public BusinessException(Throwable cause) {
        super(ErrorCode.INTERNAL_ERROR.getMessage(cause));
        this.errorCode = ErrorCode.INTERNAL_ERROR;
    }

    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public BusinessException(ErrorCode errorCode, String message) {
        super(errorCode.getMessage(message));
        this.errorCode = errorCode;
    }

    public BusinessException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode.getMessage(message), cause);
        this.errorCode = errorCode;
    }

    public BusinessException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.getMessage(cause), cause);
        this.errorCode = errorCode;
    }

}
