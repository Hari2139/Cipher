package com.hari;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Description: 
 * Created: Dec 22, 2013
 * @author Hari 
 */
public class MD5CodecTest {
	@Test
	public void testEncrypt() throws Exception {
		String encryptedPwd = MD5Codec.encrypt("MySecretPwd");
		System.out.println(encryptedPwd);
	}

	@Test
	public void testDecrypt() throws Exception {
		String encryptedPwd = MD5Codec.encrypt("MySecretPwd");
		String decryptedPwd = MD5Codec.decrypt(encryptedPwd);
		assertEquals(decryptedPwd, "MySecretPwd");
	}
}
