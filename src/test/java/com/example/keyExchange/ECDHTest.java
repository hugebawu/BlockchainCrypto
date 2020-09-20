/**
 * 
 */
package com.example.keyExchange;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.keyExchange.ECDH;
import cn.edu.ncepu.crypto.utils.CommonUtils;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 19, 2020 4:15:27 PM
 * @ClassName ECDHJUnitTest
 * @Description:  (elliptic curve based Diffie-Hellman key exchange algorithm test)
 */
public class ECDHTest {
	private static final Logger logger = LoggerFactory.getLogger(DHTest.class);
	private static final String EC_STRING = "EC";
	private static final String CURVE_NAME = "secp256k1";

	@Ignore
	@Test
	/**
	 * @Description:  (test shared key generation method) 参数描述
	 * @throws
	 */
	public void testGenSharedKey() {
		try {
			logger.info("Testing ECDH key exchange scheme.");
			// Alice generate key pair
			KeyPair keyPair_Alice = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			PublicKey publicKey_Alice = keyPair_Alice.getPublic();
			PrivateKey privateKey_Alice = keyPair_Alice.getPrivate();

			// Bob generate key pair
			KeyPair keyPair_Bob = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			PublicKey publicKey_Bob = keyPair_Bob.getPublic();
			PrivateKey privateKey_Bob = keyPair_Bob.getPrivate();

			// generate two related shared key and compare if they are the same
			String sharedKey_Alice;
			sharedKey_Alice = ECDH.genSharedKey(publicKey_Bob, privateKey_Alice);
			String sharedKey_Bob = ECDH.genSharedKey(publicKey_Alice, privateKey_Bob);

			if (sharedKey_Alice.equals(sharedKey_Bob)) {
				logger.info("ECDH key exchange functionality test pass.");
			}
			assertEquals(sharedKey_Alice, sharedKey_Bob);
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
