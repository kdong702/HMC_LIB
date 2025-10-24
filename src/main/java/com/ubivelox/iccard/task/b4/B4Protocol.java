package com.ubivelox.iccard.task.b4;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.task.HmcProtocol;
import lombok.*;

import java.util.HashMap;


@Getter
public class B4Protocol {
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

        @Override
        public HmcProtocol.Response generateResponse(HmcProtocol.Request request, String resCode, HashMap<String, String> resultMap) {
            return new Response(resCode, resultMap.get(Constants.PUT_APDU), resultMap.get(Constants.MAC));
        }

        @Override
        public HmcProtocol.Response generateError(String resCode) {
            return new Response(resCode, "", "");
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
        @FieldData(fieldName = "Put key APDU", length = 42)
        private String putKeyApdu;
        @FieldData(fieldName = "MAC", length = 8)
        private String mac;
    }
}
