package com.lotson.cas.utils;

import com.lotson.cas.pkcs.constant.PkcsMechanism;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.StringTokenizer;

@Slf4j
public class ByteUtils {

    private static final String HEXSTRING[] = {"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
            "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
            "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
            "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
            "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
            "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
            "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
            "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
            "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
            "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
            "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
            "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
            "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"};


    private static final byte[] HEXAVALUE = new byte[]{99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99, 99, 99, 99, 99, 99,
            99, 10, 11, 12, 13, 14, 15, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 10, 11, 12, 13, 14, 15, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99};
    private static final String TAG = ByteUtils.class.getSimpleName();
    public static final byte ASCIICODE_BYTE_ZERO = (byte) 0x30;

    /**
     * <pre>
     * Int -> Byte[]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param value
     * @return
     * @exception
     * @date 2014. 3. 12. 오후 3:40:16
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static byte[] toBytes(int value) {

        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(value);
        buffer.flip();

        byte[] data = new byte[4];
        buffer.get(data);

        return data;
    }

    /**
     * <pre>
     * Long -> Byte[]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param value
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 8:55:37
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static byte[] toBytes(long value) {

        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(value);
        buffer.flip();

        byte[] data = new byte[8];
        buffer.get(data);

        return data;
    }

    /**
     * <pre>
     * Short -> Byte[]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param value
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 8:56:03
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static byte[] toBytes(short value) {

        ByteBuffer buffer = ByteBuffer.allocate(2);
        buffer.putLong(value);
        buffer.flip();

        byte[] data = new byte[2];
        buffer.get(data);

        return data;
    }

    /**
     * <pre>
     * byte 배열을 Short 타입으로 변환
     * [이부분은 메쏘드 설명 부분입니다]
     * @param src
     * @return
     * @exception
     * @date 2014. 3. 12. 오후 2:56:45
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static short toShort(byte[] src, int srcPos) {
        ByteBuffer buffer = ByteBuffer.allocate(2);
        buffer.put(src, srcPos, 2);
        buffer.flip();

        return buffer.getShort();
    }

    /**
     * Concatenates two bytes in a byte array to form a short value.
     *
     * @param bArray byte array.
     * @param bOff   offset within byte array containing first byte (the high order byte).
     * @return the short value - the concatenated result
     */
    public static short getShort(byte[] bArray, short bOff) {
        return (short) (((short) (bArray[bOff]) << 8) +
                ((short) (bArray[(short) (bOff + 1)]) & 0xFF));
    }

    /**
     * <pre>
     * Byte -> Int
     * [이부분은 메쏘드 설명 부분입니다]
     * @param src
     * @return
     * @exception
     * @date 2014. 3. 12. 오후 2:57:11
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static int toInt(byte src) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(src);
        buffer.flip();

        return buffer.getInt();
    }

    /**
     * <pre>
     * Byte[] -> Int
     * [이부분은 메쏘드 설명 부분입니다]
     * @param src
     * @return
     * @exception
     * @date 2014. 3. 12. 오후 3:30:08
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static int toInt(byte[] src, int srcPos) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.put(src, srcPos, 4);
        buffer.flip();

        return buffer.getInt();
    }

    /**
     * <pre>
     * Byte[] -> Long
     * [이부분은 메쏘드 설명 부분입니다]
     * @param src
     * @param srcPos
     * @return
     * @exception
     * @date 2014. 3. 12. 오후 3:32:44
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static long toLong(byte[] src, int srcPos) {

        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(src, srcPos, 8);
        buffer.flip();

        return buffer.getLong();
    }

    /**
     * <pre>
     * [숫자(String)을 byte[]로 변환]
     * [숫자(String)을 특정 진수 byte[]로 변환한다.]
     * @param digits 숫자(String)
     * @param radix 진수
     * @return 변환된 byte[]
     * @throws IllegalArgumentException
     * @throws NumberFormatException
     * @exception
     * @date 2013. 1. 7. 오후 2:21:43
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static byte[] toBytes(String digits, int radix)
            throws IllegalArgumentException, NumberFormatException {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 매개변수 체크
        if (digits == null) {
            return null;
        }

        // 변환할 진수 체크 (16, 10, 8 진수만 가능)
        if (radix != 16 && radix != 10 && radix != 8) {
            throw new IllegalArgumentException("For input radix: \"" + radix + "\"");
        }

        // 바이트 길이 계산
        int divLen = (radix == 16) ? 2 : 3;
        int length = digits.length();

        if (length % divLen == 1) {
            throw new IllegalArgumentException("For input string: \"" + digits + "\"");
        }

        length = length / divLen;
        byte[] bytes = new byte[length];

        // 진법 변환
        for (int i = 0; i < length; i++) {
            int index = i * divLen;
            bytes[i] = (byte) (Short.parseShort(digits.substring(index, index + divLen), radix));
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return bytes;
    }

    /**
     * <pre>
     * [10진수(String)을 byte[]로 변환]
     * [10진수(String)을 byte[]로 변환한다.]
     * @param digits 16진수 (String Array)
     * @return 변환된 byte[]
     * @throws IllegalArgumentException
     * @throws NumberFormatException
     * @exception
     * @date 2013. 1. 7. 오후 2:23:28
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static byte[] toBytesFromHexString(String[] digits) {

        ByteArrayOutputStream bao = new ByteArrayOutputStream();

        for (int i = 0; i < digits.length; i++) {
            byte[] data = toBytesFromHexString(digits[i]);
            bao.write(data, 0, data.length);
        }

        return bao.toByteArray();
    }

    /**
     * <pre>
     * [10진수(String)을 byte[]로 변환]
     * [10진수(String)을 byte[]로 변환한다.]
     * @param digits 16진수(String)
     * @return 변환된 byte[]
     * @throws IllegalArgumentException
     * @throws NumberFormatException
     * @exception
     * @date 2013. 1. 7. 오후 2:23:28
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static byte[] toBytesFromHexString(String digits)
            throws IllegalArgumentException, NumberFormatException {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 매개변수 체크
        if (digits == null || digits.isEmpty()) {
            return null;
        }

        // 길이 가져오기
        if (digits.startsWith("KISA/")) {
            digits = digits.substring(5);
        }

        int length = digits.length();
        if (length % 2 == 1) {
            throw new IllegalArgumentException("For input string: \"" + digits + "\"");
        }

        // 바이트 길이 계산
        length = length / 2;
        byte[] bytes = new byte[length];

        // 진법 변환
        for (int i = 0; i < length; i++) {
            int index = i * 2;
            bytes[i] = (byte) (Short.parseShort(digits.substring(index, index + 2), 16));
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return bytes;
    }

    /**
     * <pre>
     * [byte를 10진수(String)으로 변환]
     * [byte를 10진수(String)으로 변환한다.]
     * @param b byte
     * @return 10진수(String)
     * @exception
     * @date 2013. 1. 7. 오후 2:37:25
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    private static String toHexString(byte b) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // byte를 10진수로 변환
        StringBuffer result = new StringBuffer(3);
        result.append(Integer.toString((b & 0xF0) >> 4, 16));
        result.append(Integer.toString(b & 0x0F, 16));

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return result.toString();
    }

    /**
     * <pre>
     * [byte[]를 16진수로 변환]
     * [byte[]를 16진수로 변환한다.]
     * @param bytes byte[]
     * @return 16진수
     * @exception
     * @date 2013. 1. 7. 오후 3:00:45
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static String toHexString(byte[] bytes) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 인자값 체크
        if (bytes == null) {
            return null;
        }

        // 10진수 변환
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) {
            result.append(Integer.toString((b & 0xF0) >> 4, 16));
            result.append(Integer.toString(b & 0x0F, 16));
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return result.toString().toUpperCase();
    }

    /**
     * <pre>
     * [byte[]를 16진수로 변환(특정위치)]
     * [byte[]에서 특정위치에 있는 byte[]를 10진수로 변환한다.]
     * @param bytes byte[]
     * @param offset 특정위치
     * @param length 길이
     * @return 16진수
     * @exception
     * @date 2013. 1. 7. 오후 3:02:30
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static String toHexString(byte[] bytes, int offset, int length) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        if (bytes == null) {
            return null;
        }

        // 10진수 변환
        StringBuffer result = new StringBuffer();
        for (int i = offset; i < offset + length; i++) {
            result.append(Integer.toString((bytes[i] & 0xF0) >> 4, 16));
            result.append(Integer.toString(bytes[i] & 0x0F, 16));
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return result.toString().toUpperCase();
    }


    /**
     * <pre>
     * [char를 byte로 변환]
     * [char를 byte로 변환한다.]
     * @param c char
     * @return 변환된 byte
     * @exception
     * @date 2013. 1. 7. 오후 3:46:35
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    private static byte toByte(char c) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "" );

        switch (c) {
            case '0':
                return 0;
            case '1':
                return 1;
            case '2':
                return 2;
            case '3':
                return 3;
            case '4':
                return 4;
            case '5':
                return 5;
            case '6':
                return 6;
            case '7':
                return 7;
            case '8':
                return 8;
            case '9':
                return 9;
            case 'A':
                return 10;
            case 'B':
                return 11;
            case 'C':
                return 12;
            case 'D':
                return 13;
            case 'E':
                return 14;
            case 'F':
                return 15;
            default:
                break;
        }

        return 0;
    }

    /**
     * <pre>
     * Int -> Byte
     * [ 4 바이트 중에 한 바이트만 반환 ]
     * @param value
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 8:58:14
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static byte toByte(int value) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // byte의 범위가 넘어서는 경우 처리
        if (value < 0 || 256 < value)
            return 0;

        // int를 byte로 변환
        ByteBuffer buffer = ByteBuffer.allocate(Integer.SIZE / 8);
        buffer.putInt(value);

        // BIG_ENDIAN으로 설정
        buffer.order(ByteOrder.BIG_ENDIAN);
        byte[] result = buffer.array();

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return result[3];
    }

    /**
     * <pre>
     * [byte를 Int로 변환]
     * [1byte 값을 4byte int 값으로 변환
     * (주의 : byte 값 범위:0~256)]
     * @param value byte
     * @return 변환된 Int
     * @exception
     * @date 2013. 1. 7. 오후 3:47:49
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static int toByte(byte value) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 결과 생성 및 초기화
        byte[] temp = new byte[4];
        for (int i = 0; i < 3; i++) {
            temp[i] = ASCIICODE_BYTE_ZERO;
        }
        temp[3] = value;

        // byte 설정
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer = ByteBuffer.wrap(temp);

        // BIG_ENDIAN으로 설정
        buffer.order(ByteOrder.BIG_ENDIAN);

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return buffer.getInt();
    }

    /**
     * <pre>
     * [십진수(String)을 byte로 변환]
     * [십진수(String)을 byte로 변환한다.]
     * @param hexStr 십진수(String)
     * @return 변환된 byte
     * @exception
     * @date 2013. 1. 7. 오후 3:45:10
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static byte toByte(String hexStr) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 변수 초기화
        byte result = 0;
        String hex = hexStr.toUpperCase();

        // 10진수를 byte로 변환
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(hex.length() - i - 1);
            byte b = toByte(c);
            result |= (b & 0x0f) << (i * 4);
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return result;
    }

    /**
     * <pre>
     * [Int를 String으로 변환]
     * [Int를 String으로 변환한다.]
     * @param data Int
     * @return String
     * @exception
     * @date 2013. 1. 7. 오후 4:28:10
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static String toHexStringFromInt(int data) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "" );

        byte temp1 = ByteUtils.toByte(data);
        return ByteUtils.toHexString(temp1);
    }

    /**
     * <pre>
     * Int -> Byte[]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param value
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 8:58:58
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static byte[] intToByteArray(int value) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte one = (byte) (value >>> 24);
        byte two = (byte) (value >>> 16);
        byte three = (byte) (value >>> 8);
        byte four = (byte) (value);

        boolean found = false;

        if (one > 0x00) {
            baos.write(one);
            found = true;
        }
        if (found || two > 0x00) {
            baos.write(two);
            found = true;
        }

        if (found || three > 0x00) {
            baos.write(three);
            found = true;
        }

        baos.write(four);

        return baos.toByteArray();
    }

    /**
     * <pre>
     * String -> HexaByte[]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param encoded
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 8:59:46
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static byte[] fromHexString(String encoded) {
        encoded = removeSpaces(encoded);
        if (encoded.length() == 0) {
            return new byte[0];
        }
        if ((encoded.length() % 2) != 0) {
            throw new IllegalArgumentException("Input string must contain an even number of characters: " + encoded);
        }
        final byte result[] = new byte[encoded.length() / 2];
        final char enc[] = encoded.toCharArray();
        for (int i = 0; i < enc.length; i += 2) {
            StringBuilder curr = new StringBuilder(2);
            curr.append(enc[i]).append(enc[i + 1]);
            result[i / 2] = (byte) Integer.parseInt(curr.toString().toUpperCase(), 16);
        }
        return result;
    }

    /**
     * <pre>
     * 문자열 공백제거
     * [이부분은 메쏘드 설명 부분입니다]
     * @param s
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:00:09
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String removeSpaces(String s) {
        StringTokenizer st = new StringTokenizer(s, " ", false);
        StringBuilder buf = new StringBuilder();
        while (st.hasMoreElements()) {
            buf.append(st.nextElement());
        }
        return buf.toString().toUpperCase();
    }

    /**
     * <pre>
     * [String을 byte(BIG ENDIAN)로 변환]
     * [String을 byte(BIG ENDIAN)로 변환한다.]
     * @param s 원 문자열
     * @return 변환된 byte
     * @exception
     * @date 2013. 1. 7. 오후 4:21:39
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static byte[] changeStringToByte(String s) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 결과값 선언 및 초기화
        byte[] res = new byte[s.length() / 2];

        // String을 byte로 변환
        int cnt = 0;
        for (int i = 0; i < s.length(); i += 2) {
            String strTmp = s.substring(i, i + 2);
            int iTmp = Integer.valueOf(strTmp, 16);
            ByteBuffer bb = ByteBuffer.allocate(Integer.SIZE / 8);
            bb.putInt(iTmp);
            bb.order(ByteOrder.BIG_ENDIAN);
            byte[] bTmp = bb.array();
            byte tmp2 = bTmp[Integer.SIZE / 8 - 1];

            res[cnt] = tmp2;
            cnt++;
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return res;
    }

    /**
     * <pre>
     * [byte[]를 String으로 변환]
     * [byte[]를 String으로 변환한다.]
     * @param data byte[]
     * @return String
     * @exception
     * @date 2013. 1. 7. 오후 3:49:50
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public synchronized static String changeString(byte[] data) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 결과값 선언
        String res = "";

        // 인자값 체크
        if (data == null) {
            return res;
        }

        // byte를 String으로 변환
        try {
            for (int i = 0; i < data.length; i++) {
                ByteBuffer bb = ByteBuffer.allocate(1);
                bb = ByteBuffer.wrap(data, i, 1);
                byte tmp = bb.get();

                res += String.format("%02X", tmp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return res;
    }

    /**
     * <pre>
     * [byte[] (UICC)를 UICC로 변환]
     * [byte[] (UICC)를 UICC(String)으로 변환한다.]
     * @param data byte[] (UICC)
     * @return UICC (String)
     * @exception
     * @date 2013. 1. 7. 오후 3:48:46
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static String swapAndConvertToStringUICC(byte[] data) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 결과값 초기화
        StringBuffer res = new StringBuffer();

        // byte를 String으로 변환
        for (int i = 0; i < data.length - 2; i++) {
            ByteBuffer bb = ByteBuffer.allocate(1);
            bb = ByteBuffer.wrap(data, i, 1);
            byte tmp = bb.get();
            byte hTmp = (byte) ((tmp & 0xF0) >> 4);
            byte lTmp = (byte) ((tmp & 0x0F) << 4);

            tmp = (byte) (hTmp | lTmp);

            res.append(String.format("%02x", tmp));
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return res.toString().toUpperCase();
    }

    /**
     * <pre>
     * Byte[] -> Int
     * [이부분은 메쏘드 설명 부분입니다]
     * @param byteArray
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:00:40
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static int byteArrayToInt(byte[] byteArray) {
        return byteArrayToInt(byteArray, 0, byteArray.length);
    }

    /**
     * <pre>
     * Byte[] -> Int
     * 지정된 지점부터 크기만큼 Int로 변환
     * @param byteArray
     * @param startPos
     * @param length
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:00:52
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static int byteArrayToInt(byte[] byteArray, int startPos, int length) {
        if (byteArray == null) {
            throw new IllegalArgumentException("Parameter 'byteArray' cannot be null");
        }
        if (length <= 0 || length > 4) {
            throw new IllegalArgumentException("Length must be between 1 and 4. Length = " + length);
        }
        int value = 0;
        for (int i = startPos; i < length; i++) {
            value += ((byteArray[i] & 0xFF) << 8 * (byteArray.length - i - 1));
        }
        return value;
    }

    // ====================================================================
    // 모바일카드 최적화 추가
    // ====================================================================
    public static boolean isBitSet(byte val, int bitPos) {
        if (bitPos < 1 || bitPos > 8) {
            throw new IllegalArgumentException("parameter 'bitPos' must be between 1 and 8. bitPos=" + bitPos);
        }
        if ((val >> (bitPos - 1) & 0x1) == 1) {
            return true;
        }
        return false;
    }

    /**
     * <pre>
     * Byte -> String
     * 앞자리 0으로 채우기
     * @param val
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:02:32
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String byte2BinaryLiteral(byte val) {
        String s = Integer.toBinaryString(toInt(val));
        if (s.length() < 8) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8 - s.length(); i++) {
                sb.append('0');
            }
            sb.append(s);
            s = sb.toString().toUpperCase();
        }
        return s;
    }

    /**
     * <pre>
     * [메쏘드 한글명을 적어주세요]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param byteArray
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:03:31
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String getSafePrintChars(byte[] byteArray) {
        if (byteArray == null) {
            //return "" instead?
            throw new IllegalArgumentException("Argument 'byteArray' cannot be null");
        }
        return getSafePrintChars(byteArray, 0, byteArray.length);
    }

    /**
     * <pre>
     * [메쏘드 한글명을 적어주세요]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param byteArray
     * @param startPos
     * @param length
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:04:18
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String getSafePrintChars(byte[] byteArray, int startPos, int length) {
        if (byteArray == null) {
            //return "" instead?
            throw new IllegalArgumentException("Argument 'byteArray' cannot be null");
        }
        if (byteArray.length < startPos + length) {
            throw new IllegalArgumentException("startPos(" + startPos + ")+length(" + length + ") > byteArray.length(" + byteArray.length + ")");
        }
        StringBuilder buf = new StringBuilder();
        for (int i = startPos; i < length; i++) {
            if (byteArray[i] >= (byte) 0x20 && byteArray[i] < (byte) 0x7F) {
                buf.append((char) byteArray[i]);
            } else {
                buf.append(".");
            }
        }
        return buf.toString().toUpperCase();
    }

    /**
     * <pre>
     * [메쏘드 한글명을 적어주세요]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param in
     * @param indent
     * @param wrapLines
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:04:29
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String prettyPrintHex(String in, int indent, boolean wrapLines) {
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            buf.append(c);
        }
        return buf.toString().toUpperCase();
    }

    /**
     * <pre>
     * [메쏘드 한글명을 적어주세요]
     * [이부분은 메쏘드 설명 부분입니다]
     * @param in
     * @param indent
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:04:31
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String prettyPrintHex(String in, int indent) {
        return prettyPrintHex(in, indent, false);
    }

    /**
     * <pre>
     * Byte[] -> HexaString
     * [이부분은 메쏘드 설명 부분입니다]
     * @param data
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:04:33
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String prettyPrintHex(byte[] data) {
        return prettyPrintHex(byteArrayToHexString(data), 0, false);
    }

    /**
     * <pre>
     * Byte[] -> HexaString
     * [이부분은 메쏘드 설명 부분입니다]
     * @param byteArray
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:04:36
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String byteArrayToHexString(final byte[] byteArray) {
        if (byteArray == null) {
            return "";
        }
        return byteArrayToHexString(byteArray, 0, byteArray.length);
    }

    /**
     * <pre>
     * Byte[] -> HexaString
     * [이부분은 메쏘드 설명 부분입니다]
     * @param byteArray
     * @param startPos
     * @param length
     * @return
     * @exception
     * @date 2014. 5. 27. 오후 9:04:38
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String byteArrayToHexString(final byte[] byteArray, int startPos, int length) {
        if (byteArray == null) {
            return "";
        }
        if (byteArray.length < startPos + length) {
            throw new IllegalArgumentException("startPos(" + startPos + ")+length(" + length + ") > byteArray.length(" + byteArray.length + ")");
        }
        //        int readBytes = byteArray.length;
        StringBuilder hexData = new StringBuilder();
        int onebyte;
        for (int i = 0; i < length; i++) {
            onebyte = ((0x000000ff & byteArray[startPos + i]) | 0xffffff00);
            hexData.append(Integer.toHexString(onebyte).substring(6));
        }
        return hexData.toString().toUpperCase();
    }

    /**
     * <pre>
     * [바이트 초기화 (특정길이)]
     * [바이트를 초기화한다.]
     * @param length 길이
     * @return byte[]
     * @exception
     * @date 2013. 1. 7. 오후 3:07:15
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static byte[] getClearByte(int length) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 특정 길이만큼 byte를 초기화한다.
        byte[] temp = new byte[length];
        for (int i = 0; i < temp.length; i++) {
            temp[i] = 0x20;
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return temp;
    }

    /**
     * <pre>
     * [바이트 초기화 (특정길이, 특정위치)]
     * [바이트를 초기화한다.]
     * @param length 길이
     * @param offer 특정위치
     * @return byte[]
     * @exception
     * @date 2013. 1. 7. 오후 3:07:46
     * @author 이제원
     * @비고
     *
     * </pre>
     */
    public static byte[] getClearByte(int length, byte offer) {
        // --------------------------------------------------------------------
        // # 시작로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "{" );

        // 특정 길이만큼 byte를 초기화한다.
        byte[] temp = new byte[length];
        for (int i = 0; i < temp.length; i++) {
            temp[i] = offer;
        }

        // --------------------------------------------------------------------
        // # 종료로그
        // --------------------------------------------------------------------
        //Logger.dnfo( "}" );
        return temp;
    }

    /**
     * <pre>
     * 2바이트씩 잘라 16진수로 변환후
     * [이부분은 메쏘드 설명 부분입니다]
     * @param hexString
     * @return
     * @throws Exception
     * @exception
     * @date 2014. 5. 27. 오후 9:06:34
     * @author Administrator
     * @비고
     *
     * </pre>
     */
    public static String convertHexToString(String hexString)
            throws Exception {
        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();

        for (int i = 0; i < hexString.length() - 1; i += 2) {
            String output = hexString.substring(i, (i + 2));
            int decimal = Integer.parseInt(output, 16);
            sb.append((char) decimal);
            temp.append(decimal);
        }
        return sb.toString().toUpperCase();
    }

    /**
     * @param hex
     * @return string
     */
    public static String hexStringToString(String hex) {
        int l = hex.length();
        byte[] data = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return new String(data);
    }

    /**
     * <pre>
     * 우측으로 PAD
     * [이부분은 메쏘드 설명 부분입니다]
     * @param str
     * @param len
     * @param addStr
     * @return
     * @exception
     * @date 2013. 9. 4. 오후 4:31:32
     * @author AT솔루션즈
     * @비고
     *
     * </pre>
     */
    public static String padRight(String str, int len, String addStr) {
        String result = str;
        int tempLen = 0;
        if (result != null) {
            tempLen = len - result.length();
        } else {
            return "";
        }

        if (tempLen <= 0) {
            return result;
        }

        for (int i = 0; i < tempLen; i++) {
            result = result + addStr;
        }

        return result;
    }

    /**
     * <pre>
     * 좌측으로 PAD
     * [이부분은 메쏘드 설명 부분입니다]
     * @param str
     * @param len
     * @param addStr
     * @return
     * @exception
     * @date 2013. 9. 4. 오후 4:35:27
     * @author 윤동근
     * @비고
     *
     * </pre>
     */
    public static String padLeft(String str, int len, String addStr) {
        String result = str;
        int tempLen = 0;
        if (result != null) {
            tempLen = len - result.length();
        } else {
            return "";
        }

        if (tempLen <= 0) {
            return result;
        }

        for (int i = 0; i < tempLen; i++) {
            result = addStr + result;
        }

        return result;
    }

    public static byte[] copyByteArray(byte[] array2Copy) {
        //        byte[] copy = new byte[array2Copy.length];
        //        System.arraycopy(array2Copy, 0, copy, 0, array2Copy.length);
        //        return copy;
        if (array2Copy == null) {
            //return new byte[0] instead?
            throw new IllegalArgumentException("Argument 'array2Copy' cannot be null");
        }
        return copyByteArray(array2Copy, 0, array2Copy.length);
    }

    public static byte[] copyByteArray(byte[] array2Copy, int startPos, int length) {
        if (array2Copy == null) {
            //return new byte[0] instead?
            throw new IllegalArgumentException("Argument 'array2Copy' cannot be null");
        }
        if (array2Copy.length < startPos + length) {
            throw new IllegalArgumentException("startPos(" + startPos + ")+length(" + length + ") > byteArray.length(" + array2Copy.length + ")");
        }
        byte[] copy = new byte[array2Copy.length];
        System.arraycopy(array2Copy, startPos, copy, 0, length);
        return copy;
    }

    public static String int2Hex(int i) {
        String hex = Integer.toHexString(i);
        if (hex.length() < 2) {
            hex = "0" + hex;
        }
        return hex;
    }

    /**
     * <pre>
     * 1. Summary : String 에 대해 packedBytes를 반환한다.
     * 2. Details : String 에 대해 packedBytes를 반환한다.
     * 3. LastModifiedDate : 2015. 6. 10.
     * 4. LastReviewedDate : 2015. 6. 10.
     * 5. History
     *      2015. 6. 10. Exception 처리
     * </pre>
     *
     * @param data pack 하려는 원본 데이터로 Hexa String 문자열 이어야 함
     * @return pack 된 결과를 byte[]로 리턴, 형식에 맞지 않는 데이터가 들어오면 Exception
     * @Method Name : getPackedBytes
     */
    public static byte[] getPackedBytes(final String data) {
        if (!isHexaString(data)) {
            throw new RuntimeException("data[" + data + "] is not hexa string.");
        }

        byte[] result = new byte[data.length() / 2];

        for (int i = 0; i < result.length; ++i) {
            result[i] = (byte) ((HEXAVALUE[data.charAt(i * 2)] << 4) + HEXAVALUE[data.charAt(i * 2 + 1)]);
        }

        return result;
    }


    /**
     * <pre>
     * 1. Summary : 주어진 byte data 에 대해 unpacked string 을 반환한다.
     * 2. Details : 주어진 byte data 에 대해 unpacked string 을 반환한다.
     *
     * 3. LastModifiedDate : 2015. 6. 11.
     * 4. LastReviewedDate : 2015. 6. 11.
     * 5. History
     *      2015. 6. 11. Exception 처리
     *
     * </pre>
     *
     * @param data
     * @return unpack 된 결과를 String 으로 리턴, data 가 null 이거나 없으면 exception 발생
     * @Method Name : getUnpackedString
     */
    public static String getUnpackedString(final byte[] data) {
        if (isEmpty(data)) {
            throw new RuntimeException("data is empty.");
        }

        StringBuffer result = new StringBuffer(data.length * 2);

        for (int i = 0; i < data.length; i++) {
            result.append(HEXSTRING[(int) data[i] & 0xFF]);
        }

        return result.toString().toUpperCase();
    }


    /**
     * <pre>
     * 1. Summary : 주어진 String 이 null 또는 빈 문자열인지 확인한다.
     * 2. Details : 주어진 String 이 null 또는 빈 문자열인지 확인한다.
     * 3. LastModifiedDate : 2015. 6. 10.
     * 4. LastReviewedDate : 2015. 6. 10.
     * 5. History
     *      2015. 6. 10. 3항 연산자 사용
     * </pre>
     *
     * @param data
     * @return null 이거나 빈 문자열이면 true, 아니면 false
     * @Method Name : isEmpty
     */
    public static boolean isEmpty(final String data) {
        return (data == null || data.isEmpty()) ? true : false;
    }

    /**
     * <pre>
     * 1. Summary : 주어진 String 이 hex 값인지 확인한다.
     * 2. Details : 주어진 String 이 hex 값인지 확인한다.
     * 3. LastModifiedDate : 2015. 6. 10.
     * 4. LastReviewedDate : 2015. 6. 10.
     * 5. History
     *      2015. 6. 10. || 연산자 사용하여 if 문 두개를 한개로 수정
     * </pre>
     *
     * @param data
     * @return 주어진 문자열이 Hexa String 이면 true, 아니면 false
     * @Method Name : isHexaString
     */
    public static boolean isHexaString(final String data) {
        if (isEmpty(data) || (data.length() & 0x01) == 1) {
            return false;
        }

        for (int i = 0; i < data.length(); ++i) {
            if (data.charAt(i) > 255 || 99 == HEXAVALUE[data.charAt(i)]) {
                return false;
            }
        }

        return true;
    }

    /**
     * <pre>
     * 1. Summary : 주어진 byte[] 에 대해 null 도 아니고 길이도 0이 아닌지 확인한다.
     * 2. Details : 주어진 byte[] 에 대해 null 도 아니고 길이도 0이 아닌지 확인한다.
     * 3. LastModifiedDate : 2015. 6. 10.
     * 4. LastReviewedDate : 2015. 6. 10.
     * 5. History
     * 		2015. 6. 10. 신규 작성
     * </pre>
     *
     * @param data
     * @return 주어진 byte[] 에 대해 null 도 아니고 길이도 0이면 true, 아니면 false
     * @Method Name : isEmpty
     */
    public static boolean isEmpty(final byte[] data) {
        return (data == null || data.length == 0) ? true : false;
    }

    public static byte[] xor(byte[] data) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ 0xff);
        }
        return result;
    }

    public static byte[] xor(byte[] bytes1, byte[] bytes2) {
        byte[] result = new byte[bytes1.length];
        for (int i = 0; i < bytes1.length; i++) {
            result[i] = (byte) (bytes1[i] ^ bytes2[i]);
        }
        return result;
    }

    public static int findIndex(byte[] byteArray, byte searchValue) {
        int index = -1; // initialize the index to -1 (not found)
        for (int i = 0; i < byteArray.length; i++) {
            if (byteArray[i] == searchValue) {
                index = i; // update the index if the value is found
                break; // exit the loop if the value is found
            }
        }
        return index;
    }

    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static String textToHex(String text, String charsetName) {
        byte[] bytes = new byte[0];
        try {
            bytes = text.getBytes(charsetName);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return bytesToHex(bytes);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString().toUpperCase();
    }

    public static byte[] toFill(byte[] item, byte fix, int len) {
        byte[] data = new byte[item.length + len];
        Arrays.fill(data, 0, len, fix);
        System.arraycopy(item, 0, data, len, item.length);
        return data;
    }

    public static byte[] toFillLeft(byte[] item, byte fix, int totalLen) {
        byte[] data = new byte[totalLen];
        Arrays.fill(data, 0, totalLen - item.length, fix);
        System.arraycopy(item, 0, data, totalLen - item.length, item.length);
        return data;
    }

    public static byte[] toFillRight(byte[] item, byte fix, int totalLen) {
        byte[] data = new byte[totalLen];
        Arrays.fill(data, item.length, totalLen, fix);
        System.arraycopy(item, 0, data, 0, item.length);
        return data;
    }

    public static byte[] add128Padding(int len) {
        byte[] data = new byte[len];
        //Arrays.fill(data, 0, len, (byte) 0x00);
        data[0] = (byte) 0x80;
        return data;
    }

    public static byte[] add128Padding(byte[] data, int totalLen) {
        byte[] temp = new byte[totalLen];
        System.arraycopy(data, 0, temp, 0, data.length);
        temp[data.length] = (byte) 0x80;
        return temp;
    }

    public static byte[] addPadding(byte[] data, int totalLen, byte padding) {
        byte[] temp = new byte[totalLen];
        Arrays.fill(data, 0, totalLen, padding);
        System.arraycopy(data, 0, temp, 0, data.length);

        return temp;
    }

    public static byte[] copyArray(byte[] data1, byte[] data2) {
        int length1 = data1.length;
        int length2 = data2.length;

        byte[] result = new byte[length1 + length2];

        System.arraycopy(data1, 0, result, 0, length1);
        System.arraycopy(data2, 0, result, length1, length2);
        return result;
    }

    public static byte[] copyArrays(byte[]... data) {
        int totalLength = 0;
        for (byte[] bytes : data) {
            totalLength += bytes.length;
        }

        byte[] result = new byte[totalLength];
        int pos = 0;
        for (byte[] bytes : data) {
            System.arraycopy(bytes, 0, result, pos, bytes.length);
            pos += bytes.length;
        }
        return result;
    }

    public static byte[] copyArraysWithPad80(PkcsMechanism IPkcsMechanism, byte[]... data) {
        int blockSize = IPkcsMechanism.getBlockSize();
        return HexUtils.pad80(copyArrays(data), blockSize);
    }

    public static byte[] copyArray(byte[] data1, byte[] data2, int length1, int length2) {
        byte[] result = new byte[length1 + length2];

        System.arraycopy(data1, 0, result, 0, length1);
        System.arraycopy(data2, 0, result, length1, length2);
        return result;
    }

    public static byte[] copyArrayWithPad(byte[] data1, byte[] data2, int size) {
        byte[] copyArray = copyArray(data1, data2);
        if (copyArray.length > size) {
            throw new RuntimeException("copyArray의 길이가 size 보다 깁니다.");
        }
        byte[] result = add128Padding(copyArray, size);
        return result;
    }

    /**
     * 단순 2글자 합치는 메서드 HexUtils.toByteArray(str1 + str2) 사용
     */
    public static byte[] copyToByteArrayWithPad(String str1, String str2, int size) {
        byte[] data1 = HexUtils.toByteArray(str1);
        byte[] data2 = HexUtils.toByteArray(str2);
        return copyArrayWithPad(data1, data2, size);
    }

    public static byte[] copyToByteArrayWithPad(String str1, String str2, int length1, int length2, int size) {
        byte[] data1 = HexUtils.toByteArray(str1);
        byte[] data2 = HexUtils.toByteArray(str2);

        byte[] copyArray = new byte[length1 + length2];

        System.arraycopy(data1, 0, copyArray, 0, length1);
        System.arraycopy(data2, 0, copyArray, length1, length2);
        byte[] result = add128Padding(copyArray, size);

        return result;
    }

    public static byte[] cutByteArray(byte[] array2Copy, int startPos, int length) {
        byte[] copy = new byte[length];
        System.arraycopy(array2Copy, startPos, copy, 0, length);
        return copy;
    }

}
