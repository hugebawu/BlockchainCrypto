/**
 * 
 */
package com.example.encryption.ecies;

import static org.junit.Assert.assertEquals;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.ecies.ECIESEngine;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 19, 2020 4:20:39 PM
 * @ClassName ECIESEngineJUniteTest
 * @Description: TODO(elliptic curve integrated encryption scheme test)
 */
public class ECIESEngineJUniteTest {
	private static Logger logger = LoggerFactory.getLogger(ECIESEngineJUniteTest.class);
	private static String USER_DIR = SysProperty.USER_DIR;
	private static final String EC_STRING = "EC";

	@Ignore
	@Test
	public void testECIES_Encrypt_Eecrypt() {
		try {
			PublicKey publicKey = null;
			PrivateKey privateKey = null;
			publicKey = (PublicKey) CommonUtils.loadKeyFromPEM(true, EC_STRING, USER_DIR + "/elements/publicKey.pem");
			privateKey = (PrivateKey) CommonUtils.loadKeyFromPEM(false, EC_STRING,
					USER_DIR + "/elements/privateKey.pem");
			String content = "cryptography12342qer45taredfghdfghj/？！#@￥##%……";
			// encrypt the ciphertext can be transmitted directly through network.
			String ciphertext = ECIESEngine.encrypt(content, publicKey);
			System.out.println("plaintext: " + content);
			System.out.println("base64 ciphertext: " + ciphertext);
			System.out.println("base64 ciphertext length: " + ciphertext.length());
			// decrypt
			String decryptedtext = ECIESEngine.decrypt(ciphertext, privateKey);
			System.out.println("decrypted plaintext: " + decryptedtext);
			assertEquals(content, decryptedtext);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
