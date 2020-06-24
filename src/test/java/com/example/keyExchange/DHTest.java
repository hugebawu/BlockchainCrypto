/**
 * 
 */
package com.example.keyExchange;

import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import org.junit.Ignore;
import org.junit.Test;

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

	@Ignore
	@Test
	/**
	 * @Description: TODO(test shared key generation method)
	 * @throws
	 */
	public void testGenSharedKey() {
		System.out.println("Testing DH key exchange scheme.");
		int keysize = 3072;
		// Alice generate key pair
		KeyPair keyPair_Alice = DH.getDHKeyPair(keysize);
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
	}
}
