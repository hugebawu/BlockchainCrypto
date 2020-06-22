/**
 * 
 */
package com.example.keyExchange;

import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

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
 * @Description: TODO(elliptic curve Diffie-Hellman key exchange algorithm test)
 */
public class ECDHTest {

//	@Ignore
	@Test
	/**
	 * @Description: TODO(test shared key generation method) 参数描述
	 * @throws
	 */
	public void testGenSharedKey() {
		// TODO Auto-generated method stub
		System.out.println("Testing ECDH key exchange scheme.");
		// generate key pair 1
		KeyPair keyPair1 = ECUtils.getKeyPair();
		PublicKey publicKey1 = keyPair1.getPublic();
		PrivateKey privateKey1 = keyPair1.getPrivate();

		// generate key pair 2
		KeyPair keyPair2 = ECUtils.getKeyPair();
		PublicKey publicKey2 = keyPair2.getPublic();
		PrivateKey privateKey2 = keyPair2.getPrivate();

		// generate two related shared key and compare if they are the same
		String sharedKey1 = ECDH.genSharedKey(publicKey1, privateKey2);
		String sharedKey2 = ECDH.genSharedKey(publicKey2, privateKey1);

		if (sharedKey1.equals(sharedKey2)) {
			System.out.println("ECDH key exchange functionality test pass.");
		}
		assertEquals(sharedKey1, sharedKey2);
	}
}
