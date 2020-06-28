/**
 * 
 */
package com.example.keyExchange;

import static org.junit.Assert.assertEquals;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.keyExchange.DH;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 25, 2020 12:10:12 AM
 * @ClassName DHTest
 * @Description: TODO(Diffie-Hellman key exchange algorithm test)
 */
public class DHTest {

	private static Logger logger = LoggerFactory.getLogger(DHTest.class);

	@Ignore
	@Test
	/**
	 * TODO(test shared key generation method)
	 */
	public void testGenSharedKey() {
		try {
			System.out.println("Testing DH key exchange scheme.");
			int keysize = 3072;
			// Alice generate key pair
			KeyPair keyPair_Alice;
			keyPair_Alice = DH.getDHKeyPair(keysize);
			PublicKey publicKey_Alice = keyPair_Alice.getPublic();
			PrivateKey privateKey_Alice = keyPair_Alice.getPrivate();

			// Bob generate key pair
			KeyPair keyPair_Bob = DH.getDHKeyPair(keysize);
			PublicKey publicKey_Bob = keyPair_Bob.getPublic();
			PrivateKey privateKey_Bob = keyPair_Bob.getPrivate();

			// Alice generate shared key according to the public key received from Bob
			String base64_publciKey_Bob = Base64.getEncoder().encodeToString(publicKey_Bob.getEncoded());
			String sharedKey_Alice = DH.genSharedKey(base64_publciKey_Bob, privateKey_Alice);

			// Bob generate shared key according to the public key received from Alice
			String base64_publciKey_Alice = Base64.getEncoder().encodeToString(publicKey_Alice.getEncoded());
			String sharedKey_Bob = DH.genSharedKey(base64_publciKey_Alice, privateKey_Bob);

			// and compare if they are the same
			if (sharedKey_Alice.equals(sharedKey_Bob)) {
				System.out.println("DH key exchange functionality test pass.");
			}
			assertEquals(sharedKey_Alice, sharedKey_Bob);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeySpecException e) {
			logger.error(e.getLocalizedMessage());
		} catch (DecoderException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
