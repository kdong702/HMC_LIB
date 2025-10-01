package com.ubivelox.iccard.task.protocol;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.common.Constants;
import lombok.*;

import java.util.HashMap;


@Getter
public class B3 {
    @Getter
    @Setter
    @ToString
    public static class Request implements HmcProtocol.Request {

        @FieldData(fieldName = "Key Version", length = 2)
        private String keyVersion;
        @FieldData(fieldName = "CSN", length = 16)
        private String csn;
        @FieldData(fieldName = "CRN", length = 32)
        private String crn;
        @FieldData(fieldName = "Record", length = 2)
        private String record;
        @FieldData(fieldName = "Account Status Code", length = 2)
        private String accountStatusCode;
        @FieldData(fieldName = "Account Number", length = 104)
        private String accountNumber;
        @FieldData(fieldName = "Account Start Position", length = 2)
        private String expireDate;
        @FieldData(fieldName = "Account Count", length = 2)
        private String accountCount;

        @Override
        public HmcProtocol.Response generateResponse(HmcProtocol.Request request, String resCode, HashMap<String, String> resultMap) {
            return new Response(resCode, resultMap.get(Constants.UPDATE_APDU), resultMap.get(Constants.MAC));
        }

        @Override
        public HmcProtocol.Response generateError(String resCode) {
            return new Response(resCode, "errorTest", "");
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
        @FieldData(fieldName = "UPDATE APDU", length = 138)
        private String updateApdu;
        @FieldData(fieldName = "MAC", length = 8)
        private String mac;
    }
}
