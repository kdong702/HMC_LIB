package com.ubivelox.iccard.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class Base64Utils {

    private Base64Utils() {}

    public static String encode(String plain) {
        if (plain == null) return null;
        return Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
    }

    public static String decode(String base64) {
        if (base64 == null) return null;
        byte[] dec = Base64.getDecoder().decode(base64);
        return new String(dec, StandardCharsets.UTF_8);
    }

    /**
     * 입력이 유효한 Base64면 디코딩 결과 반환, 아니면 원본 반환.
     */
    public static String decodeIfBase64(String maybeBase64) {
        if (maybeBase64 == null) return null;
        try {
            return decode(maybeBase64);
        } catch (IllegalArgumentException e) {
            return maybeBase64;
        }
    }

    public static String decodeEnc(String slotPassword) {
        if(StringUtils.startsWith(slotPassword, "ENC")) {
            log.info("Detected ENC(...) wrapped  encoded slot password.");
            String base64 = Base64Utils.stripEncWrapper(slotPassword);
            slotPassword = Base64Utils.decodeIfBase64(base64);
        }
        return slotPassword;
    }

    private static final Pattern ENC_WRAPPER = Pattern.compile("(?i)^\\s*ENC\\s*\\(\\s*(.+?)\\s*\\)\\s*$");

    public static String stripEncWrapper(String s) {
        if (s == null) return null;
        Matcher m = ENC_WRAPPER.matcher(s);
        if (m.matches()) {
            String inner = m.group(1);
            return inner == null ? "" : inner.trim();
        }
        return s;
    }

}
