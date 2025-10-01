package com.lotson.hmc.pkcs.constant;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

@Getter
@AllArgsConstructor
public enum IPkcsPadding {

    NO_PADDING          ("NO_PADDING",                            "NO") {
        @Override
        byte[] pad(byte[] plainText, int blockSize) {
            return plainText;
        }

        @Override
        byte[] unPad(byte[] plainText, int blockSize) {
            return plainText;
        }
    },
    NR_PADDING          ("NR_PADDING",                            "NR") {
        @Override
        byte[] pad(byte[] plainText, int blockSize) {
            return nrPad(plainText, blockSize);
        }

        @Override
        byte[] unPad(byte[] plainText, int blockSize) {
            return unpad80(plainText, blockSize);
        }
    },
    FULL_PADDING        ("FULL_PADDING",                          "FULL") {
        @Override
        byte[] pad(byte[] plainText, int blockSize) {
            return fullPad(plainText, blockSize);
        }

        @Override
        byte[] unPad(byte[] plainText, int blockSize) {
            return unpad80(plainText, blockSize);
        }
    },
    PKCS_PADDING        ("PKCS#7",                                "PKCS") {
        @Override
        byte[] pad(byte[] plainText, int blockSize) {
            return pkcsPadding(plainText , blockSize);
        }

        @Override
        byte[] unPad(byte[] plainText, int blockSize) {
            return pkcsUnpadding(plainText, blockSize);
        }
    },
    ;
    private final String name;
    private final String alias;
    abstract byte[] pad(byte[] plainText, int blockSize);
    abstract byte[] unPad(byte[] plainText, int blockSize);

    public static byte[] padding(String code, byte[] plainText, int blockSize) {
        if (StringUtils.isBlank(code)) {
            throw new RuntimeException(String.format("Argument[%s] code is blank", code));
        }
        for (IPkcsPadding iPkcsPadding : IPkcsPadding.values()) {
            if (StringUtils.equals(iPkcsPadding.getAlias(),code)) {
                return iPkcsPadding.pad(plainText, blockSize);
            }
        }
        throw new RuntimeException(String.format("Not found Code[%s]", code));
    }

    public static byte[] unPadding(String code, byte[] plainText, int blockSize) {
        if (StringUtils.isBlank(code)) {
            throw new RuntimeException(String.format("Argument[%s] code is blank", code));
        }
        for (IPkcsPadding iPkcsPadding : IPkcsPadding.values()) {
            if (StringUtils.equals(iPkcsPadding.getAlias(),code)) {
                return iPkcsPadding.unPad(plainText, blockSize);
            }
        }
        throw new RuntimeException(String.format("Not found Code[%s]", code));
    }


    public static byte[] nrPad(byte data[] ,int blockSize) {
        int remainder = data.length % blockSize;
        int length = data.length;
        if (remainder > 0 || (remainder == 0 && data[data.length - 1] == -128)) {
            length += blockSize - remainder;
            byte padding[] = new byte[blockSize];
            padding[0] = -128;
            byte paddedData[] = new byte[length];
            System.arraycopy(data, 0, paddedData, 0, data.length);
            System.arraycopy(padding, 0, paddedData, data.length, blockSize - remainder);
            return paddedData;
        } else {
            return data;
        }
    }

    public static byte[] fullPad(byte data[] ,int blockSize) {
        int remainder = data.length % blockSize;
        int length = data.length;

        length += blockSize - remainder;
        byte padding[] = new byte[blockSize];
        padding[0] = -128;
        byte paddedData[] = new byte[length];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        System.arraycopy(padding, 0, paddedData, data.length, blockSize - remainder);
        return paddedData;
    }

    public static byte[] pkcsPadding(byte[] source, int blockSize) {
        int paddingCnt = source.length % blockSize;
        byte[] paddingResult = null;

        paddingResult = new byte[source.length + (blockSize - paddingCnt)];

        System.arraycopy(source, 0, paddingResult, 0, source.length);

        // 패딩해야 할 갯수 - 1 (마지막을 제외)까지 0x00 값을 추가한다.
        int addPaddingCnt = blockSize - paddingCnt;
        for (int i = 0; i < addPaddingCnt; i++) {
            paddingResult[source.length + i] = (byte) addPaddingCnt;
        }

        return paddingResult;
    }

    /**
     * 패킷내 정의된 필드의 길이가 남을때 0x00으로 채운다
     *
     * @param b : 대상 바이트 배열
     * @param length : 필드 길이
     */
    public static byte[] byteLengthPadding(byte[] b, int length)
    {
        int size = b.length;
        byte[] data = null;
        if (size == length)
        {
            data = b;
        }
        else if (size < length)
        {
            data = new byte[length];
            System.arraycopy(b, 0, data, 0, size);
            for (int i = size; i < length; i++)
            {
                data[ i] = (byte) 0x00;
            }
        }
        else if (size > length)
        {
            data = new byte[length];
            System.arraycopy(b, 0, data, 0, length);
        }
        return data;
    }

    public static byte[] unpad80(byte data[], int blockSize) {
        int padPosition = -1;
        int startPosition = data.length - blockSize;
        startPosition = startPosition <= 0 ? 0 : startPosition;
        byte b80 = -128;
        byte b00 = 0;
        for (int i = data.length - 1; i >= startPosition; i--) {
            if (data[i] == b80) {
                padPosition = i;
                break;
            }
            if (data[i] != b00)
                break;
        }

        byte unpadData[];
        if (padPosition > 0) {
            unpadData = new byte[padPosition];
            System.arraycopy(data, 0, unpadData, 0, padPosition);
        } else {
            unpadData = new byte[data.length];
            System.arraycopy(data, 0, unpadData, 0, data.length);
        }
        return unpadData;
    }

    public static byte[] pkcsUnpadding(byte data[], int blockSize) {
        int padPosition = -1;
        int startPosition = data.length - blockSize;
        startPosition = startPosition <= 0 ? 0 : startPosition; // padding 된 블록까지만 짜르기
        int lastValue = data[data.length-1];

        startPosition = startPosition + blockSize -lastValue; // for문 돌때 패딩 값 이전에  padding 된 거 체크,

        if(lastValue <= blockSize) { // 마지막 값이 blockSize 과 비교, 작으면 pkcsPadding 된 상태 일수 있음 아니면 패딩 아님.
            for(int i = data.length - 1; i >= startPosition; i--) {
                if (data[i] == lastValue) {
                    padPosition = i;
                }
                if (data[i] != lastValue) {
                    break;
                }
            }
        }

        byte unpadData[];
        if (padPosition > 0) {
            unpadData = new byte[padPosition];
            System.arraycopy(data, 0, unpadData, 0, padPosition);
        } else {
            unpadData = new byte[data.length];
            System.arraycopy(data, 0, unpadData, 0, data.length);
        }
        return unpadData;
    }
}
