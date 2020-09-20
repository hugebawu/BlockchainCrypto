/**
 * 
 */
package com.example.encryption.SymCrypt.pbe;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.SymCrypt.pbe.PBEEngine;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 24, 2020 9:21:41 PM
 * @ClassName PBEEngineTest
 * @Description:  (password based encryption)
 */
public class PBEEngineTest {
	private static final Logger logger = LoggerFactory.getLogger(PBEEngineTest.class);

	@Ignore
	@Test
	public void testPBE() {
		// plaintext
		String message = "Message";
		logger.info("Message = " + message);
		String password = "Ttkx123";
		// 16 bytes random salt
		try {
			byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
			logger.info("16 bytes Hex salt: " + Hex.toHexString(salt));
			System.out.printf("16 bytes salt: %032x\n", new BigInteger(1, salt));
			// encryption
			// example "PBEwithSHA1And128bitAES-CBC-BC"
			String digest_alg = "SHA256";
			String enc_alg = "256bitAES-CBC-BC";
			byte[] encrypted = PBEEngine.enc_dec_PBE(true, digest_alg, enc_alg, password, salt,
					message.getBytes(StandardCharsets.UTF_8));
			logger.info("Encrypted Ciphertext = " + Base64.getEncoder().encodeToString(encrypted));
			// decryption
			byte[] decrypted = PBEEngine.enc_dec_PBE(false, digest_alg, enc_alg, password, salt, encrypted);
			String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);
			logger.info("Decrypted Plaintext = " + decryptedMessage);
			assertEquals(message, decryptedMessage);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeySpecException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalBlockSizeException e) {
			logger.error(e.getLocalizedMessage());
		} catch (BadPaddingException e) {
			logger.error(e.getLocalizedMessage());
		}

	}
}
