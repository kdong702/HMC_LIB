package com.lotson.cas.utils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class HexUtils {
    static final char[] hexorder = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    private static final String[] bHex = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E",
            "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};
    private static final byte[] hexaValue = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14,
            15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
    static String[] pseudo = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};

    public static String toHexString(int value) {
        long conv = value;
        return toHexString(conv, 8);
    }

    public static String toHexString(byte value) {
        long conv = value;
        return toHexString(conv, 2);
    }

    public static String longToHexString(long value, int byteSize) {
        return String.format("%0" + (byteSize * 2) + "x", value).toUpperCase();
    }

    public static String toHexString(short value) {
        long conv = value;
        return toHexString(conv, 4);
    }

    public static String toHexString(long value, int length) {
        StringBuffer sb = new StringBuffer();

        for (int i = length; i > 0; --i) {
            int pow = power(16, i);
            int idx = (int) (value / pow);
            value %= pow;
            sb.append(hexorder[idx]);
        }
        return sb.toString();
    }

    public static String toHexString(byte[] in) {
        return toHexString(in, in.length);
    }

    public static String toHexString(byte[] in, int pos, int nValueLen) {
        byte ch = 0;

        int i = 0;
        if ((in == null) || (nValueLen <= 0) || in.length < pos + nValueLen)
            return null;

        StringBuffer out = new StringBuffer(nValueLen * 2);
        while (i < nValueLen) {
            ch = (byte) (in[pos + i] & 0xF0);
            ch = (byte) (ch >>> 4);
            ch = (byte) (ch & 0xF);
            out.append(pseudo[ch]);

            ch = (byte) (in[pos + i] & 0xF);
            out.append(pseudo[ch]);

            ++i;
        }

        String rslt = new String(out);
        return rslt;
    }

    public static String toHexString(byte[] in, int nValueLen) {
        byte ch = 0;

        int i = 0;
        if ((in == null) || (nValueLen <= 0))
            return null;

        StringBuffer out = new StringBuffer(nValueLen * 2);
        while (i < nValueLen) {
            ch = (byte) (in[i] & 0xF0);
            ch = (byte) (ch >>> 4);
            ch = (byte) (ch & 0xF);
            out.append(pseudo[ch]);

            ch = (byte) (in[i] & 0xF);
            out.append(pseudo[ch]);

            ++i;
        }

        String rslt = new String(out);
        return rslt;
    }

    public static String toHexStringPad(byte[] in, int outLen, byte pad) {
        return toHexStringPad(in, in == null ? 0 : in.length, outLen, pad);
    }

    public static String toHexStringPad(byte[] in, int nValueLen, int outLen, byte pad) {
        byte ch = 0;
        int i = 0;

        byte[] newBuf = new byte[outLen];

        if (in != null) {
            if (nValueLen >= outLen) {
                nValueLen = outLen;
            } else {
                Arrays.fill(newBuf, nValueLen, outLen, pad);
            }
            System.arraycopy(in, 0, newBuf, 0, nValueLen);
        }
        return toHexString(newBuf, nValueLen);
    }


    public static byte[] toByteArray(String str) {
        int len = str.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[(i / 2)] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));

        return data;
    }

    public static int toByteArray(String str, byte[] outBuf, int offset) {
        int len = str.length();
        int result = str.length() / 2;
        for (int i = 0; i < len; i += 2) {
            outBuf[offset + (i / 2)] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return result;
    }

    static int power(int value, int times) {
        int ret = value;
        --times;
        if (times < 1)
            return 1;
        for (int i = 1; i < times; ++i)
            ret *= value;
        return ret;
    }

    public static long parseHexString(String str) throws IOException {
        return parseHexString(str, 0, str.length());
    }

    public static long parseHexString(String str, int sidx, int length) throws IOException {
        int sum = 0;
        str.toUpperCase();
        for (int i = sidx; i < length; ++i) {
            if (sum * 16 > 9223372036854775807L) {
                throw new IOException("0x" + str.substring(sidx, length) + " is out of manageable range("
                        + -9223372036854775808L + "~" + 9223372036854775807L + ")");
            }

            char ch = str.charAt(i);
            if ((ch >= '0') && (ch <= '9'))
                sum = sum * 16 + ch - '0';
            else if ((ch >= 'A') && (ch <= 'F'))
                sum = sum * 16 + ch + '\n' - 65;
            else
                throw new IOException(ch + " in string '" + str.substring(sidx, length) + "' is not hex code.");
        }

        return sum;
    }

    public static int toInt(byte value) {
        return ((value < 0) ? 256 + value : value);
    }

    public static int toInt(char val) {
        byte value = (byte) val;
        return ((value < 0) ? 256 + value : value);
    }

    public static char[] hexStringToCharArray(String str, boolean isLittleEndian) throws IOException {
        int length = str.length() / 2;
        char[] ret = new char[length];
        if (isLittleEndian) {
            for (int i = 0; i < length; ++i)
                ret[i] = (char) (int) parseHexString(str, i * 2,
                        ((i + 1) * 2 < str.length()) ? (i + 1) * 2 : str.length());

            return ret;
        }
        return ret;
    }

    public static boolean isHexString(String data) {
        int i = 0;

        for (i = 0; i < data.length(); ++i)
            if ((data.charAt(i) > 255) || (-1 == hexaValue[data.charAt(i)]))
                return false;

        return true;
    }

    public static byte[] getPackedBytes(String data) {
        byte[] result = null;
        if ((data.length() % 2 == 0) && (isHexString(data))) {
            result = new byte[data.length() / 2];
            for (int i = 0; i < data.length(); i += 2)
                result[(i / 2)] = (byte) ((hexaValue[data.charAt(i)] << 4) + hexaValue[data.charAt(i + 1)]);

        }

        return result;
    }

    public static String convertStringToHex(String str) {
        char[] chars = str.toCharArray();

        StringBuffer hex = new StringBuffer();
        for (int i = 0; i < chars.length; ++i) {
            hex.append(Integer.toHexString(chars[i]));
        }

        return hex.toString();
    }

    public static String convertHexToString(String hex) {
        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();

        for (int i = 0; i < hex.length() - 1; i += 2) {
            String output = hex.substring(i, i + 2);

            int decimal = Integer.parseInt(output, 16);

            sb.append((char) decimal);

            temp.append(decimal);
        }

        return sb.toString();
    }

    public static byte calcLRC(ArrayList<Byte> arraylist) {
        byte bLRC = 0;

        for (int i = 3; i < arraylist.size() - 1; ++i)
            bLRC = (byte) (bLRC ^ ((Byte) arraylist.get(i)).byteValue());
        return bLRC;
    }

    public static byte calcLRC(byte[] bySRC, int nLen, int nOffset) {
        byte bLRC = 0;
        for (int i = nOffset; i < nLen + nOffset; ++i)
            bLRC = (byte) (bLRC ^ bySRC[i]);
        return bLRC;
    }

    public static byte[] getRandom(int size) {
        byte[] result = new byte[size];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(result);
        return result;
    }

    public static String padRight(String s, int n) {
        return String.format("%1$-" + n + "s", s);
    }

    public static String padLeft(String s, int n) {
        return String.format("%1$" + n + "s", s);
    }

    public static String spacePadding(String s, int n) {
        StringBuffer sb = new StringBuffer();
        sb.append(s);
        for (int i = 0; i < n; i++) {
            sb.append(" ");
        }
        return sb.toString();
    }

    public static byte[] addPadding(byte[] source, int blockSize)
    {
        int paddingCnt = source.length % blockSize;
        byte[] paddingResult = null;

        if (paddingCnt != 0) {
            paddingResult = new byte[source.length + (blockSize - paddingCnt)];

            System.arraycopy(source, 0, paddingResult, 0, source.length);

            // 패딩해야 할 갯수 - 1 (마지막을 제외)까지 0x00 값을 추가한다.
            int addPaddingCnt = blockSize - paddingCnt;
            for (int i = 0; i < addPaddingCnt; i++) {
                paddingResult[source.length + i] = (byte) addPaddingCnt;
            }
        } else {
            paddingResult = source;
        }

        return paddingResult;
    }

    public static byte[] padNull(byte data[], int blockSize) {
        int remainder = data.length % blockSize;
        int length = data.length;
        if (remainder > 0) {
            length += blockSize - remainder;
            byte padding[] = new byte[blockSize];
            byte paddedData[] = new byte[length];
            System.arraycopy(data, 0, paddedData, 0, data.length);
            System.arraycopy(padding, 0, paddedData, data.length, blockSize - remainder);
            return paddedData;
        } else {
            return data;
        }
    }

    public static byte[] pad80(byte data[], int blockSize) {
        int remainder = data.length % blockSize;
        int length = data.length;
        if (remainder > 0) {
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

    public static byte[] findLastBlockData(byte data[], int blockSize, int findSize ) {
        int share = (int) Math.ceil((double) data.length / blockSize);
        byte[] target = new byte[findSize];
        System.arraycopy(data, blockSize * (share - 1), target, 0, findSize);
        return target;
    }

    public static byte[] makeOddParity(byte[] bySrc) {
        int nInputDataLen = bySrc.length;
        byte[] byTemp = new byte[nInputDataLen];
        int i = 0;
        byte b = 0;
        for (i = 0; i < nInputDataLen; i++) {
            b = bySrc[i];
            byTemp[i] = (byte) ((b & 0xfe) | ((((b >> 1) ^ (b >> 2) ^ (b >> 3) ^ (b >> 4) ^ (b >> 5) ^ (b >> 6) ^ (b >> 7)) ^ 0x01) & 0x01));
        }
        return byTemp;
    }

    public static String maskData(String data, int from, int to, char maskWith) {

        StringBuilder maskedPart = new StringBuilder();
        for(int i=from; i<to; i++)
            maskedPart.append(maskWith);

        return data.replace(data.substring(from, to), maskedPart.toString());
    }
}
