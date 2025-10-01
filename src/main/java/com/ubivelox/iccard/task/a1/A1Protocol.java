package com.ubivelox.iccard.task.a1;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.annotation.MaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.task.a2.A2Protocol;
import com.ubivelox.iccard.task.HmcProtocol;
import lombok.*;

import java.util.HashMap;


@Getter
public class A1Protocol {
    @Getter
    @Setter
    @ToString
    public static class Request implements HmcProtocol.Request {

//        @ToString.Exclude
        @FieldData(fieldName = "TRN", length = 16)
        private String trn;
        @FieldData(fieldName = "Initialize Update Data", length = 56)
        private String initData;

        @Override
        public HmcProtocol.Response generateResponse(HmcProtocol.Request request, String resCode, HashMap<String, String> resultMap) {
            return new Response(resCode, resultMap.get(Constants.APDU));
        }

        @Override
        public HmcProtocol.Response generateError(String resCode) {
            return new A2Protocol.Response(resCode, "errorTest", "");
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
        @MaskData(start = 0, end = 26)
        @FieldData(fieldName = "인증 APDU", length = 42)
        private String apdu;
    }
}
