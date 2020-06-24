/**
 * 
 */
package com.example.encryption.pbe;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import cn.edu.ncepu.crypto.encryption.pbe.PBEEngine;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 24, 2020 9:21:41 PM
 * @ClassName PBEEngineTest
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
public class PBEEngineTest {

//	@Ignore
	@Test
	public void testPBE() {
		// plaintext
		String message = "Message";
		System.out.println("Message = " + message);
		String password = "Ttkx123";
		// 16 bytes random salt
		try {
			byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
			System.out.println("16 bytes Hex salt: " + Hex.toHexString(salt));
			System.out.printf("16 bytes salt: %032x\n", new BigInteger(1, salt));
			// encryption
			// example "PBEwithSHA1And128bitAES-CBC-BC"
			String digest_alg = "SHA256";
			String enc_alg = "256bitAES-CBC-BC";
			byte[] encrypted = PBEEngine.enc_dec_PBE(true, digest_alg, enc_alg, password, salt,
					message.getBytes("UTF8"));
			System.out.println("Encrypted Ciphertext = " + Base64.getEncoder().encodeToString(encrypted));
			// decryption
			byte[] decrypted = PBEEngine.enc_dec_PBE(false, digest_alg, enc_alg, password, salt, encrypted);
			String decryptedMessage = new String(decrypted, "UTF-8");
			System.out.println("Decrypted Plaintext = " + decryptedMessage);
			assertEquals(message, decryptedMessage);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

	}
}
