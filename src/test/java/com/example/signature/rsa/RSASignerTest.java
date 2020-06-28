/**
 * 
 */
package com.example.signature.rsa;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.rsa.RSAEncEngine;
import cn.edu.ncepu.crypto.signature.rsa.RSASigner;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 25, 2020 2:36:03 PM
 * @ClassName RSASignerTest
 * @Description: TODO(RSA digit signature test)
 */
public class RSASignerTest {
	private static Logger logger = LoggerFactory.getLogger(RSASignerTest.class);

//	@Ignore
	@Test
	public void testRSASigner() {
		try {
			logger.info("Test RSA signature.");
			// keyGen
			int keysize = 1024;
			KeyPair keyPair = RSAEncEngine.getRSAKeyPair(keysize);
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
			logger.info("Hex privateKey length = " + Hex.encodeHexString(rsaPrivateKey.getEncoded()).length());

			logger.info("========================================");
			logger.info("Test signer functionality");

			String message = "Message";
			logger.info("message: " + message);
			// signature
			byte[] signed = RSASigner.signRSA(rsaPrivateKey, message.getBytes("UTF-8"));
			String signature = Base64.getEncoder().encodeToString(signed);
			logger.info("Base64 signature: " + signature);
			logger.info("Base64 Signature length = " + signature.length());

			// verify
			assertTrue(RSASigner.verifyRSA(rsaPublicKey, message.getBytes("UTF-8"), signed));
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
		logger.info("ECDSA signer functionality test pass.");
	}
}
