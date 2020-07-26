/**
 * 
 */
package com.example.encryption.ecies;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.ecies.ECIESEngine;
import cn.edu.ncepu.crypto.utils.EccUtils;

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

	ECIESEngine engine = ECIESEngine.getInstance();

	@Ignore
	@Test
	public void testECIES_Encrypt_Eecrypt() {
		try {
			KeyPair keyPair = EccUtils.getKeyPair(256);

			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

			// 生成一个Base64编码的公钥字符串，可用来传输
			String ecBase64PublicKey = EccUtils.publicKey2String(publicKey);
			String ecBase64PrivateKey = EccUtils.privateKey2String(privateKey);
			logger.info("[publickey]:\t" + ecBase64PublicKey);
			logger.info("[privateKey]:\t" + ecBase64PrivateKey);

			// 从base64编码的字符串恢复密钥
			ECPublicKey publicKey2 = EccUtils.string2PublicKey(ecBase64PublicKey);
			ECPrivateKey privateKey2 = EccUtils.string2PrivateKey(ecBase64PrivateKey);

			String content = "cryptography12342qer45taredfghdfghj/？！#@￥##%……";
			byte[] contentBytes = content.getBytes("UTF-8");
			// encrypt the ciphertext can be transmitted directly through network.
			byte[] ciphertextBytes = engine.encrypt(contentBytes, publicKey2);
			// for transmission encode cipherText as Base64
			String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);
			logger.info("plaintext: " + content);
			logger.info("base64 ciphertext: " + ciphertext);
			logger.info("base64 ciphertext length: " + ciphertext.length());
			// decrypt
			String decryptedtext = new String(engine.decrypt(ciphertext, privateKey2), "UTF-8");
			logger.info("decrypted plaintext: " + decryptedtext);
			assertEquals(content, decryptedtext);
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeySpecException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalBlockSizeException e) {
			logger.error(e.getLocalizedMessage());
		} catch (BadPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		}
	}
}
