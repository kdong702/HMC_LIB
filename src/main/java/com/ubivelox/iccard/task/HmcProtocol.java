package com.ubivelox.iccard.task;


import com.ubivelox.iccard.annotation.FieldData;
import com.ubivelox.iccard.annotation.MaskData;
import com.ubivelox.iccard.exception.CasException;
import com.ubivelox.iccard.exception.ErrorCode;
import com.ubivelox.iccard.util.HexUtils;
import com.ubivelox.iccard.util.StreamReader;
import com.ubivelox.iccard.util.StreamWriter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Field;
import java.util.HashMap;

@Slf4j
@ToString
public final class HmcProtocol {


    public static interface Request {
        Response generateResponse(Request request, String resCode, HashMap<String, String> resultMap);

        Response generateError(String resCode);

        default void read(StreamReader sr) throws IllegalAccessException {
            Field[] declaredFields = this.getClass().getDeclaredFields();
            for (Field field : declaredFields) {
                FieldData fieldData = field.getAnnotation(FieldData.class);
                if (fieldData != null) {
                    field.setAccessible(true);

                    int length = fieldData.length();
                    String target = sr.readString(length).trim();
                    field.set(this, target);
                }
            }
        }
    }

    public static interface Response {
        default String getResult(String charset) {
            int length = this.getLength();
            StreamWriter sw = new StreamWriter(length, charset);
            this.write(sw);
            return sw.toString();
        }

        default void write(StreamWriter sw){
            Field[] declaredFields = this.getClass().getDeclaredFields();
            for (Field field : declaredFields) {
                FieldData fieldData = field.getAnnotation(FieldData.class);
                if (fieldData != null) {
                    field.setAccessible(true);
                    String value = "";
                    try {
                        value = (String) field.get(this);
                    } catch (IllegalAccessException e) {
                        throw new CasException(ErrorCode.INVALID_PROTOCOL_LENGTH);
                    }
                    int length = fieldData.length();
                    sw.write(value, length);
                }
            }
        }

        default int getLength() {
            int length = 0 ;
            Field[] declaredFields = this.getClass().getDeclaredFields();
            for (Field field : declaredFields) {
                FieldData fieldData = field.getAnnotation(FieldData.class);
                if (fieldData != null) {
                    length += fieldData.length();
                }
            }
            return length;
        }

        default String maskData() {
            StringBuilder sb = new StringBuilder();
            Field[] declaredFields = this.getClass().getDeclaredFields();
            for (int i = 0; i < declaredFields.length; i++) {
                Field field = declaredFields[i];
                MaskData maskData = field.getAnnotation(MaskData.class);
                if (maskData != null) {
                    field.setAccessible(true);
                    String value = "";
                    try {
                        value = (String) field.get(this);
                        if (value != null) {
                            sb.append(HexUtils.maskData(value, maskData.start(), maskData.end(), maskData.maskChar()));
                        }
                    } catch (IllegalAccessException e) {
                        log.error("maskError", e.getMessage());
                    }
                } else {
                    field.setAccessible(true);
                    String value = "";
                    try {
                        value = (String) field.get(this);
                        if (value != null) {
                            sb.append(value);
                        }
                    } catch (IllegalAccessException e) {
                        log.error("maskError", e.getMessage());
                    }
                }
            }
            return sb.toString();
        }
    }
}
