/**
 * 
 */
package com.example.keyExchange;

import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Ignore;
import org.junit.Test;

import cn.edu.ncepu.crypto.keyExchange.ECDH;
import cn.edu.ncepu.crypto.utils.ECUtils;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 19, 2020 4:15:27 PM
 * @ClassName ECDHJUnitTest
 * @Description: TODO(elliptic curve based Diffie-Hellman key exchange algorithm test)
 */
public class ECDHTest {

	@Ignore
	@Test
	/**
	 * @Description: TODO(test shared key generation method) 参数描述
	 * @throws
	 */
	public void testGenSharedKey() {
		System.out.println("Testing ECDH key exchange scheme.");
		// Alice generate key pair
		KeyPair keyPair_Alice = ECUtils.getECKeyPair();
		PublicKey publicKey_Alice = keyPair_Alice.getPublic();
		PrivateKey privateKey_Alice = keyPair_Alice.getPrivate();

		// Bob generate key pair
		KeyPair keyPair_Bob = ECUtils.getECKeyPair();
		PublicKey publicKey_Bob = keyPair_Bob.getPublic();
		PrivateKey privateKey_Bob = keyPair_Bob.getPrivate();

		// generate two related shared key and compare if they are the same
		String sharedKey_Alice = ECDH.genSharedKey(publicKey_Bob, privateKey_Alice);
		String sharedKey_Bob = ECDH.genSharedKey(publicKey_Alice, privateKey_Bob);

		if (sharedKey_Alice.equals(sharedKey_Bob)) {
			System.out.println("ECDH key exchange functionality test pass.");
		}
		assertEquals(sharedKey_Alice, sharedKey_Bob);
	}
}
