package com.ubivelox.iccard.task.protocol;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.annotation.MaskData;
import com.ubivelox.iccard.common.Constants;
import lombok.*;

import java.util.HashMap;


@Getter
public class B1 {
    @Getter
    @Setter
    @ToString
    public static class Request implements HmcProtocol.Request {

//        @ToString.Exclude
        @FieldData(fieldName = "Key Version", length = 2)
        private String keyVersion;
        @FieldData(fieldName = "CSN", length = 16)
        private String csn;
        @FieldData(fieldName = "CRN", length = 32)
        private String crn;
        @FieldData(fieldName = "applicationLabel", length = 16)
        private String applicationLabel;

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
        @FieldData(fieldName = "UPDATE APDU", length = 94)
        private String updateApdu;
        @FieldData(fieldName = "MAC", length = 8)
        private String mac;
    }
}
