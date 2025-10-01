package com.ubivelox.iccard.task.c0;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.task.HmcProtocol;
import lombok.*;

import java.util.HashMap;


@Getter
public class C0Protocol {
    @Getter
    @Setter
    @ToString
    public static class Request implements HmcProtocol.Request {

        @FieldData(fieldName = "CSN", length = 16)
        private String csn;
        @FieldData(fieldName = "CRN", length = 32)
        private String crn;
        @FieldData(fieldName = "TRN", length = 32)
        private String trn;
        @FieldData(fieldName = "Encrypted Password", length = 32)
        private String encPwd;
        @FieldData(fieldName = "Key Version", length = 2)
        private String keyVersion;

        @Override
        public HmcProtocol.Response generateResponse(HmcProtocol.Request request, String resCode, HashMap<String, String> resultMap) {
            return new Response(resCode, resultMap.get(Constants.PIN));
        }

        @Override
        public HmcProtocol.Response generateError(String resCode) {
            return new Response(resCode, "errorTest");
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
    }
}
