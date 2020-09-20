/**
 * 
 */
package com.example.encryption.rsa;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.rsa.RSAEncEngine;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 25, 2020 12:33:33 PM
 * @ClassName RSAEngineTest
 * @Description:  (RSA encryption scheme)
 */
public class RSAEncEngineTest {
	private static final Logger logger = LoggerFactory.getLogger(RSAEncEngineTest.class);

	@Ignore
	@Test
	/**
	 *  (test RSA encryption and decryption method)
	 * @throws
	 */
	public void test_enc_dec_RSA() {
		try {
			logger.info("Testing RSA encryption scheme scheme.");
			int keysize = 3072;
			// generate key pair
			KeyPair keyPair = RSAEncEngine.getRSAKeyPair(keysize);
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			String message = "Message";
			logger.info("Message: " + message);

			// encrypt the base64 ciphertext can be transmitted directly through network.
			String base64_publciKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
			byte[] encryptedtext = RSAEncEngine.encrypt(message.getBytes(StandardCharsets.UTF_8), base64_publciKey);
			String ciphertext = Base64.getEncoder().encodeToString(encryptedtext);
			logger.info("base64 ciphertext: " + ciphertext);
			logger.info("base64 ciphertext length: " + ciphertext.length());

			// decrypt
			String base64_privateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
			byte[] decryptedtext = RSAEncEngine.decrypt(Base64.getDecoder().decode(ciphertext), base64_privateKey);
			String decryptString = new String(decryptedtext, StandardCharsets.UTF_8);
			logger.info("decrypted plaintext: " + decryptString);
			assertEquals(message, decryptedtext);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeySpecException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalBlockSizeException e) {
			logger.error(e.getLocalizedMessage());
		} catch (BadPaddingException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
