package sso;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SSOFilter {

	public static void main(String[] args) {
		
		System.out.println("[AES128 비밀키를 사용해 인코딩, 디코딩]");
		
		/*
		 *  1. AES128 - 16BYTE 비밀키를 사용해서 데이터를 인코딩, 디코딩
		 *  2. 비밀키 - 인코딩 암호화 하는쪽과 디코딩 복호화 하는쪽이 서로 같은 키(대칭키 알고리즘)
		 *  3. Cipher - 암호화 복호화를 지원해주는 객체, AES, DES, RSA 등
		 *  4. Base64 코딩은 자체 지원해주는 객체 사용 / 경우에 따라서 apache에서 제공하는 Base64사용
		 */

		System.out.println("기존 암호 : loginasp5257");
		System.out.println("암호화 : " + getEncoding("loginasp5257"));
		System.out.println("복호화 : " + getDecoding("6PXyXdIhCxEjMD+0clA62Q=="));
	}
	
	// AES 암호화 메소드 (인코딩)
	public static String getEncoding(String data) {
		try {
			String secretKey = "0123456789abcdef";
			
			byte keyBytes[] = secretKey.getBytes();
			
			Arrays.fill(keyBytes, (byte)0x00);	// 초기값 0으로 삽입, 1차원 배열 같은 값으로 초기화.
			
			byte textBytes[] = data.getBytes("UTF-8");
			
			AlgorithmParameterSpec keySpec = new IvParameterSpec(keyBytes);
			
			SecretKeySpec newKey = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
			
			// AES/CBC/PKCS5Padding 변환은 getInstance메서드에 Cipher 객체를 AES 암호화, CBC operation mode, PKCS5 padding cheme로 초기화 요청
			// 16bit 경우 AES-128
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.ENCRYPT_MODE, newKey, keySpec);	// option(mode), key, AlgorithmParameterSpec
			
			Encoder encoder = Base64.getEncoder();	// base64로 다시 포맷해서 인코딩
			
			return encoder.encodeToString(ci.doFinal(textBytes));
			
		}catch(Exception e) {
			System.out.println(e.getMessage());
		}
		
		return "";
	}
	
	// ASE 복호화 메소드 (디코딩)
	public static String getDecoding(String data) {
		try {
			String secretKey = "0123456789abcdef";
			
			byte keyBytes[] = secretKey.getBytes();
			
			Arrays.fill(keyBytes, (byte)0x00);
			
			Decoder decoder = Base64.getDecoder();	// base64로 다시 포맷해서 디코딩
			byte textBytes[] = decoder.decode(data);
			
			AlgorithmParameterSpec keySpec = new IvParameterSpec(keyBytes);
			SecretKeySpec newKey = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
			
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, newKey, keySpec);
			
			return new String(ci.doFinal(textBytes), "UTF-8");
			
		} catch(Exception e) {
			System.out.println(e.getMessage());
		}
		return "";
	}

}
