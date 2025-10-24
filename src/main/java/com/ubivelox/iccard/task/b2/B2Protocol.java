package com.ubivelox.iccard.task.b2;

import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.common.Constants;
import com.ubivelox.iccard.task.HmcProtocol;
import lombok.*;

import java.util.HashMap;


@Getter
public class B2Protocol {
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
        @FieldData(fieldName = "Card Holder Name", length = 26)
        private String cardHolderName;
        @FieldData(fieldName = "Name ID", length = 2)
        private String nameId;
        @FieldData(fieldName = "Name Number", length = 13)
        private String nameNumber;
        @FieldData(fieldName = "Expire Date", length = 8)
        private String expireDate;
        @FieldData(fieldName = "Bank Code", length = 4)
        private String bankCode;

        @Override
        public HmcProtocol.Response generateResponse(HmcProtocol.Request request, String resCode, HashMap<String, String> resultMap) {
            return new Response(resCode, resultMap.get(Constants.UPDATE_APDU), resultMap.get(Constants.MAC));
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
        @FieldData(fieldName = "UPDATE APDU", length = 152)
        private String updateApdu;
        @FieldData(fieldName = "MAC", length = 8)
        private String mac;
    }
}
