package com.lotson.hmc.util;

import java.io.ByteArrayOutputStream;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class HexUtil
{

    public HexUtil()
    {
    }

    public static int parseInt(String s, int offset, int length, int base)
        throws NumberFormatException
    {
        int value = 0;
        if(length < 0)
            length = s.length() - offset;
        for(int i = 0; i < length; i++)
        {
            char c = s.charAt(offset + i);
            int digit = c - 48;
            if(digit < 0 || digit >= base || digit >= 10)
            {
                digit = (10 + c) - 65;
                if(digit < 10 || digit >= base)
                    digit = (10 + c) - 97;
            }
            if(digit < 0 || digit >= base)
                throw new NumberFormatException(s.substring(offset, offset + length));
            value = value * base + digit;
        }

        return value;
    }

    public static byte[] parseBytes(String s, int base)
    {
        byte bytes[] = new byte[s.length() / 2];
        for(int i = 0; i < s.length(); i += 2)
            bytes[i / 2] = (byte)parseInt(s, i, 2, base);

        return bytes;
    }

    public static byte convertHexDigit(byte b)
    {
        if(b >= 48 && b <= 57)
            return (byte)(b - 48);
        if(b >= 97 && b <= 102)
            return (byte)((b - 97) + 10);
        if(b >= 65 && b <= 70)
            return (byte)((b - 65) + 10);
        else
            return 0;
    }

    public static String viewHexString(byte b[])
    {
        return viewHexString(b, 0, b.length);
    }

    public static String viewHexString(byte b[], int offset)
    {
        return viewHexString(b, offset, b.length - offset);
    }

    public static String viewHexString(byte b[], int offset, int length)
    {
        if(b == null || offset < 0 || length < 0 || b.length < offset + length)
            return "IllegalArgument";
        StringBuffer buf = new StringBuffer();
        ByteArrayOutputStream lineBuff = new ByteArrayOutputStream();
        for(int i = offset; i < offset + length; i++)
        {
            if(i % 16 != 0)
                buf.append(' ');
            else
            if(i != 0 && i % 16 == 0)
            {
                buf.append("    |");
                buf.append(lineBuff.toString()).append("|");
                buf.append('\n');
                lineBuff.reset();
            }
            lineBuff.write((b[i] < 0 || b[i] > 32) && b[i] != 127 ? ((int) (b[i])) : 46);
            int bi = 255 & b[i];
            int c = 48 + (bi / 16) % 16;
            if(c > 57)
                c = 65 + (c - 48 - 10);
            buf.append((char)c);
            c = 48 + bi % 16;
            if(c > 57)
                c = 65 + (c - 48 - 10);
            buf.append((char)c);
        }

        if(lineBuff.size() != 0)
        {
            int remain = 16 - lineBuff.size();
            for(int j = 0; j < remain; j++)
                buf.append("   ");

            buf.append("    |");
            buf.append(lineBuff.toString());
            for(int j = 0; j < remain; j++)
                buf.append(" ");

            buf.append("|");
        }
        return buf.toString();
    }

    public static String toHexString(byte b[])
    {
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < b.length; i++)
        {
            int bi = 255 & b[i];
            int c = 48 + (bi / 16) % 16;
            if(c > 57)
                c = 65 + (c - 48 - 10);
            buf.append((char)c);
            c = 48 + bi % 16;
            if(c > 57)
                c = 65 + (c - 48 - 10);
            buf.append((char)c);
        }

        return buf.toString();
    }

    public static String toHexString(byte b[], int offset, int length)
    {
        StringBuffer buf = new StringBuffer();
        for(int i = offset; i < offset + length; i++)
        {
            int bi = 255 & b[i];
            int c = 48 + (bi / 16) % 16;
            if(c > 57)
                c = 65 + (c - 48 - 10);
            buf.append((char)c);
            c = 48 + bi % 16;
            if(c > 57)
                c = 65 + (c - 48 - 10);
            buf.append((char)c);
        }

        return buf.toString();
    }

    public static byte[] fromHexString(String s)
    {
        if(s.length() % 2 != 0)
            throw new IllegalArgumentException(s);
        byte array[] = new byte[s.length() / 2];
        for(int i = 0; i < array.length; i++)
        {
            int b = Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
            array[i] = (byte)(255 & b);
        }

        return array;
    }

    public static String byteArrayToHex(byte data[], int off, int len) throws Exception
    {
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < len; i++)
        {
            byte b = data[off + i];
            buf.append(intToChar(b >> 4 & 15));
            buf.append(intToChar(b & 15));
        }

        return buf.toString();
    }

    static char intToChar(int val) throws Exception
    {
        switch(val)
        {
        case 0: // '\0'
            return '0';

        case 1: // '\001'
            return '1';

        case 2: // '\002'
            return '2';

        case 3: // '\003'
            return '3';

        case 4: // '\004'
            return '4';

        case 5: // '\005'
            return '5';

        case 6: // '\006'
            return '6';

        case 7: // '\007'
            return '7';

        case 8: // '\b'
            return '8';

        case 9: // '\t'
            return '9';

        case 10: // '\n'
            return 'A';

        case 11: // '\013'
            return 'B';

        case 12: // '\f'
            return 'C';

        case 13: // '\r'
            return 'D';

        case 14: // '\016'
            return 'E';

        case 15: // '\017'
            return 'F';
        }
        throw new Exception("E_FORMAT_ERR");
    }

    public static byte[] hexToByteArray(String value) throws Exception
    {
        return hexToByteArray(value, 0, value.length());
    }

    public static byte[] hexToByteArray(String value, int offset, int len) throws Exception
    {
        if(len < 2 || (len % 2) != 0) {
        	return null;
        }
            
        byte result[] = new byte[len / 2];
        for(int i = 0; i < len / 2; i++)
        {
            char high = value.charAt(offset + i * 2);
            char low = value.charAt(offset + i * 2 + 1);
            result[i] = (byte)(charToInt(high) << 4 | charToInt(low));
        }

        return result;
    }

    static int charToInt(char ch) throws Exception
    {
        if(ch >= '0' && ch <= '9')
            return ch - 48;
        if(ch >= 'A' && ch <= 'F')
            return (10 + ch) - 65;
        if(ch >= 'a' && ch <= 'f')
            return (10 + ch) - 97;
        else
            throw new Exception("E_FORMAT_ERR");
    }
    
    // 문자열을 헥사 스트링으로 변환하는 메서드
    public static String stringToHex(String s) {
      String result = "";

      for (int i = 0; i < s.length(); i++) {
        result += String.format("%02X ", (int) s.charAt(i));
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


    public static byte[] toByteArray(String str) {
        int len = str.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[(i / 2)] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));

        return data;
    }


    public static void main(String[] args) {
    	
    	System.out.println("out=" + HexUtil.stringToHex("9002000004"));
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

    public static char[] getDateToCharArr(int type) {
        if(type == 0 ) {
            LocalDate now = LocalDate.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
            String today = now.format(formatter);
            return today.toCharArray();
        }else {
            String lastDay = "99991231";
            return lastDay.toCharArray();
        }
    }

    public static char[] convertAsciiToChar(byte[] asciiArr) {
        char[] charArr = new char[asciiArr.length];
        for (int i = 0; i < asciiArr.length; i++) {
            charArr[i] = (char) asciiArr[i];
        }
        return charArr;
//				Arrays.toString(charArr);
    }

    public static byte[] makeComponent(byte[] byComp1, byte[] byComp2, byte[] byComp3) {

        int i = 0;

        byte [] byTemp = new byte [byComp1.length];
        byte [] byRet = new byte [byComp1.length];

        for (i = 0; i<byComp1.length; i++) {
            byTemp[i] = (byte) (byComp1[i] ^ byComp2[i]);
        }

        for (i = 0; i<byComp1.length; i++) {
            byRet[i] = (byte) (byTemp[i] ^ byComp3[i]);
        }

        return byRet;
    }


}