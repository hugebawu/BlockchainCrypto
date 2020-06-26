/**
 * 
 */
package com.example.signature.rsa;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

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
//	@Ignore
	@Test
	public void testRSASigner() {
		System.out.println("Test RSA signature.");
		// keyGen
		int keysize = 1024;
		KeyPair keyPair = RSAEncEngine.getRSAKeyPair(keysize);
		RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
		System.out.println("Hex privateKey length = " + Hex.encodeHexString(rsaPrivateKey.getEncoded()).length());

		System.out.println("========================================");
		System.out.println("Test signer functionality");

		String message = "Message";
		System.out.println("message: " + message);
		try {
			// signature
			String sign = RSASigner.signRSA(rsaPrivateKey, message);
			System.out.println("signature: " + sign);
			System.out.println("Signature length = " + sign.length());

			// verify
			assertTrue(RSASigner.verifyRSA(rsaPublicKey, message, sign));
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("ECDSA signer functionality test pass.");
	}
}
