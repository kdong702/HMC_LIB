package com.ubivelox.iccard.task.a1;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.annotation.MaskData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.task.HmcProtocol;
import lombok.*;

import java.util.HashMap;


@Getter
public class A1Protocol {
    @Getter
    @Setter
    @ToString
    public static class Request implements HmcProtocol.Request {

        @FieldData(fieldName = "TRN", length = 16)
        private String trn;
        @FieldData(fieldName = "KDD", length = 20)
        private String kdd;
        @FieldData(fieldName = "KeyVersion", length = 2)
        private String kv;
        @FieldData(fieldName = "Secure Channel Protocol", length = 2)
        private String scp;
        @FieldData(fieldName = "SC", length = 4)
        private String sc;
        @FieldData(fieldName = "CRN", length = 12)
        private String crn;
        @FieldData(fieldName = "CC", length = 16)
        private String cc;

        public boolean isScpType01() {
            String scpType = this.getScp();

            if (!scpType.equals("01") && !scpType.equals("02")) {
                throw new CasException(ErrorCode.INVALID_SCP_TYPE);
            }

            if (scpType.equals("01") ) {
                // 결국 s2+ crn은 다 똑같은듯?
                this.crn = sc + crn;
                this.sc = "";
            }
            return scpType.equals("01");
        }

        @Override
        public HmcProtocol.Response generateResponse(HmcProtocol.Request request, String resCode, HashMap<String, String> resultMap) {
            return new Response(resCode, resultMap.get(Constants.APDU));
        }

        @Override
        public HmcProtocol.Response generateError(String resCode) {
            return new Response(resCode, "");
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
