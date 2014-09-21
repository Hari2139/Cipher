package com.hari;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.CharEncoding;
import org.apache.commons.lang.StringUtils;

/**
 * Description:
 * Created: Dec 22, 2013.
 *
 * @author Hari
 */
public class MD5Codec {
	/** The Constant PASSWORD. */
	private static final char[] PASSWORD = "ingodwetrust".toCharArray();
	/** The Constant SALT. */
	private static final byte[] SALT = { (byte) 0xde, (byte) 0x3f, (byte) 0x99,
			(byte) 0xab, (byte) 0x0f, (byte) 0x3c, (byte) 0xff, (byte) 0x4d };

	/**
	 * Base64 decode.
	 *
	 * @param aString the a string
	 * @return the byte[]
	 */
	public static byte[] base64Decode(String aString) {
		return Base64.decodeBase64(aString);
	}

	/**
	 * Base64 encode.
	 *
	 * @param bytes the bytes
	 * @return the string
	 */
	public static String base64Encode(byte[] bytes) {
		return Base64.encodeBase64String(bytes);
	}

	/**
	 * Decrypt.
	 *
	 * @param encryptedString the encrypted string
	 * @return the string
	 * @throws UnsupportedEncodingException the unsupported encoding exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 */
	public static String decrypt(String encryptedString)
			throws UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeySpecException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		if (StringUtils.isEmpty(encryptedString)) {
			return StringUtils.EMPTY;
		}
		else {
			SecretKeyFactory factory = SecretKeyFactory
					.getInstance("PBEWithMD5AndDES");
			SecretKey key = factory.generateSecret(new PBEKeySpec(PASSWORD));
			Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
			pbeCipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(SALT,
					20));
			return new String(pbeCipher.doFinal(base64Decode(encryptedString)),
					CharEncoding.UTF_8);
		}
	}

	/**
	 * Encrypt.
	 *
	 * @param aString the a string
	 * @return the string
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 * @throws UnsupportedEncodingException the unsupported encoding exception
	 */
	public static String encrypt(String aString)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		if (StringUtils.isEmpty(aString)) {
			return StringUtils.EMPTY;
		}
		else {
			SecretKeyFactory factory = SecretKeyFactory
					.getInstance("PBEWithMD5AndDES");
			SecretKey key = factory.generateSecret(new PBEKeySpec(PASSWORD));
			Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
			pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(SALT,
					20));
			return base64Encode(pbeCipher.doFinal(aString
					.getBytes(CharEncoding.UTF_8)));
		}
	}
}
