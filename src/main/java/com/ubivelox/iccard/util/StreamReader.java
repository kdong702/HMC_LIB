package com.ubivelox.iccard.util;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

@Slf4j
public class StreamReader {
	protected String charset = "utf-8";
	protected ByteArrayInputStream bis;

	byte[] TEMP_BUFFER = new byte[2048];
	
	
	public StreamReader(String data) {
		bis = new ByteArrayInputStream(data.getBytes());
	}

	public StreamReader(String data, String charset) {
		try {
			bis = new ByteArrayInputStream(data.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			log.error("data.gatBytes(charset) 오류", e);
			throw new RuntimeException("getBytes 오류");
		}
		this.charset = charset;
	}

	public StreamReader(byte[] buf) {
		bis = new ByteArrayInputStream(buf);
	}
	
	public StreamReader(byte[] buf, String charset) {
		this(buf);
		this.charset = charset;
	}
	
	public int available() {
		return bis == null?0:bis.available();
	}
	
	protected void _read(int length) throws IOException {
		if(bis.available() < length) {
			throw new IOException();
		}
		
		if(TEMP_BUFFER.length < length) {
			TEMP_BUFFER = new byte[length];
		}
		
		bis.read(TEMP_BUFFER, 0, length);
	}

	
	public byte read() throws IOException {
		if(bis.available() < 1) {
			throw new IOException();
		}
		
		return (byte)bis.read();
	}
	
	public String readString(int length)  {
		String result = null;
		try {

			_read(length);

			result = new String(TEMP_BUFFER, 0, length, charset);
		} catch (IOException e) {
			log.error("readString 오류");
			throw new RuntimeException("readString 오류");
		}
		
		return result;
	}
	
	public int readInt(int length) throws IOException, NumberFormatException {
		String result = null;
		
		_read(length);
		
		result = new String(TEMP_BUFFER, 0, length);
		
		return Integer.parseInt(result.trim());
	}
	
}
