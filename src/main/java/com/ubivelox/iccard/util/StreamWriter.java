package com.ubivelox.iccard.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayOutputStream;

@Slf4j
public class StreamWriter {
	
	protected String charset = "utf-8";
	protected byte pad = 0x20;
	
	protected ByteArrayOutputStream bos;

	public StreamWriter() {
		this(2048);
	}	
	
	public StreamWriter(int size) {
		bos = new ByteArrayOutputStream(size);
	}

	public StreamWriter(int size, String charset) {
		this(size);
		this.charset = charset;
	}
	
	public void setCharset(String charset) {
		this.charset = charset;
	}

	public void setPadChar(byte pad) {
		this.pad = pad;
	}
	
	public int size() {
		return bos.size();
	}

	public void writePadding(int length) {
		writePadding(pad, length);
	}
	
	public void writePadding(byte pad, int length) {
		for(int i = 0; i < length; i++) {
			bos.write(pad);	
		}
	}

	public void write(byte value) {
		bos.write(value);
	}

	public void writeShort(short value) {
		byte[] tmpBuf = new byte[Short.BYTES]; 
		writeShort(value, tmpBuf, 0);
		bos.write(tmpBuf, 0, Short.BYTES);
	}

	public void writeInt(int value) {
		byte[] tmpBuf = new byte[Integer.BYTES]; 
		writeInt(value, tmpBuf, 0);
		bos.write(tmpBuf, 0, Integer.BYTES);
	}
	
	public void write(byte[] value) {
		write(value, value.length);
	}
	
	protected void write(byte[] value, int length, boolean isLeftPadding, byte paddingChar) {
		if(value == null) {
			writePadding(paddingChar, length);
			return;
		}

		int realLength = value.length;
		
		if(length <= realLength) {
			bos.write(value, 0, length);
		} else {
			int padLength = length - realLength;
			
			if(isLeftPadding) {
				writePadding(paddingChar, padLength);	
				bos.write(value, 0, realLength);
			} else {
				bos.write(value, 0, realLength);
				writePadding(paddingChar, padLength);
			}
		}
	}
	
	public void write(byte[] value, int length) {
		write(value, length, false, pad);
	}

	public void write(String value, int length, boolean isLeftPadding, byte paddingChar) {
		byte[] valueData = null;
		
		if(value != null) {
			try {
				valueData = value.getBytes(charset);	
			} catch(Exception e) {}
		}
		
		write(valueData, length, isLeftPadding, paddingChar);
	}
	
	public void write(String value, int length) {		
		write(value, length, false, pad);
	}
	
	public void write(Writable writerable) {
		writerable.write(this);
	}
	
	public void write(int value, int length) {
		write(StringUtils.leftPad(Integer.toString(value), length, '0'), length);
	}
	
	public void write(Long value, int length) {
		write(StringUtils.leftPad(Long.toString(value), length, '0'), length);
	}
	
	public void writeFillZero(int value, int length) {
		String strValue = value + "";
		if(strValue.length() < length) {
			strValue = String.format("%0" + (length - strValue.length()) + "d", value);
		}
		write(strValue, length);
	}
	
	public byte[] toByteArray() {
		return bos.toByteArray();
	}

	public static void writeShort(short value, byte[] buf, int offset) {
		for (int i = 0; i < Short.BYTES; i++) {
			buf[offset + Short.BYTES - i - 1] = (byte) (value & 0xFF);
		    value >>= 8;
		}
	}

	public static void writeInt(int value, byte[] buf, int offset) {
		for (int i = 0; i < Integer.BYTES; i++) {
			buf[offset + Integer.BYTES - i - 1] = (byte) (value & 0xFF);
		    value >>= 8;
		}
	}

	public static void writePadding(byte pad, byte[] buf, int offset, int length) {
		int size = offset + length;
		size = size > buf.length ? buf.length : size;
		for(int i = offset; i < size; i++) {
			buf[i] = pad;
		}
	}
	
	public static void write(byte[] value, byte[] buf, int offset, int length, boolean isLeftPadding, byte paddingChar) {
		if(value == null) {
			writePadding(paddingChar, buf, offset, length);
			return;
		}

		int realLength = value.length;
		
		if(length <= realLength) {
			System.arraycopy(value, 0, buf, offset, length);
		} else {
			int padLength = length - realLength;
			
			if(isLeftPadding) {
				writePadding(paddingChar, buf, offset, padLength);
				System.arraycopy(value, 0, buf, offset + padLength, realLength);
			} else {
				System.arraycopy(value, 0, buf, offset, realLength);
				writePadding(paddingChar, buf, offset + realLength, padLength);
			}
		}
	}
	
	@Override
	public String toString() {
		try {
			return new String(bos.toByteArray(), 0, bos.toByteArray().length, charset);
		} catch(Exception e) {
			log.error(e.getMessage(), e);
		}
		return "";
	}

}
