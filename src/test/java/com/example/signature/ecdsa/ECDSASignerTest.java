package com.example.signature.ecdsa;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.ECUtils;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 18, 2020 3:24:26 PM
 * @ClassName ECDSASignerTest
 * @Description: TODO(elliptic curve based dsa(Digital Signature Algorithm) test.)
 */
public class ECDSASignerTest {

	@Test
	public void testECDSASigner() {
		System.out.println("Test Scott-Vanstone 1992 signature.");
		// keyGen
		KeyPair keyPair = ECUtils.getKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		System.out.println("privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());

		System.out.println("========================================");
		System.out.println("Test signer functionality");

		try {
			// signature
			String sign = ECDSASigner.signECDSA(privateKey, "message");
			System.out.println("signature: " + sign);
			System.out.println("Signature length = " + sign.length());

			// verify
			if (false == ECDSASigner.verifyECDSA(publicKey, "message", sign)) {
				System.out.println("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("ECDSA signer functionality test pass.");

		System.out.println("========================================");
		System.out.println("Test signer parameters serialization & de-serialization.");
	}

}
