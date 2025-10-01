package com.ubivelox.iccard.task.protocol;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.common.Constants;
import lombok.*;

import java.util.HashMap;


@Getter
public class C1 {
    @Getter
    @Setter
    @ToString
    public static class Request implements HmcProtocol.Request {

        @FieldData(fieldName = "CSN", length = 16)
        private String csn;
        @FieldData(fieldName = "CRN1", length = 32)
        private String crn1;
        @FieldData(fieldName = "CRN2", length = 32)
        private String crn2;
        @FieldData(fieldName = "TRN", length = 32)
        private String trn;
        @FieldData(fieldName = "Encrypted Password", length = 32)
        private String encPwd;
        @FieldData(fieldName = "Encrypted Account Number", length = 32)
        private String encAccountNum;
        @FieldData(fieldName = "Encrypted Amount", length = 32)
        private String encAmount;
        @FieldData(fieldName = "Key Version", length = 2)
        private String keyVersion;

        @Override
        public HmcProtocol.Response generateResponse(HmcProtocol.Request request, String resCode, HashMap<String, String> resultMap) {
            return new Response(resCode, resultMap.get(Constants.PIN), resultMap.get(Constants.ACCOUNT_NUMBER), resultMap.get(Constants.AMOUNT));
        }

        @Override
        public HmcProtocol.Response generateError(String resCode) {
            return new Response(resCode, "errorTest", "errorTest", "errorTest");
        }
    }

    @ToString
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Response implements HmcProtocol.Response {
        @FieldData(fieldName = "응답코드", length = 8)
        private String resCode;
        @FieldData(fieldName = "복호화된 비밀번호", length = 8)
        private String pin;
        @FieldData(fieldName = "복호화된 출금계좌번호", length = 32)
        private String accountNum;
        @FieldData(fieldName = "복호화된 출금금액", length = 32)
        private String amount;
    }
}
