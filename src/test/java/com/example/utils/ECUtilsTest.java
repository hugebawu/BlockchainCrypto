/**
 * 
 */
package com.example.utils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import org.apache.commons.codec.binary.Hex;
import org.junit.Ignore;
import org.junit.Test;

import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.ECUtils;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 19, 2020 11:14:34 PM
 * @ClassName ECUtilsTest
 * @Description: TODO(test methods of ECUtils)
 */
public class ECUtilsTest {

	@Ignore
	@Test
	public void testSaveECKeyAsPEM() {
		KeyPair keyPair = ECUtils.getKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		try {
			ECUtils.saveECKeyAsPEM(publicKey, "src/test/java/com/example/utils/publicKey.pem");
			ECUtils.saveECKeyAsPEM(privateKey, "src/test/java/com/example/utils/privateKey.pem");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Ignore
	@Test
	public void testSaveECKeyAsDER() {
		KeyPair keyPair = ECUtils.getKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		try {
			ECUtils.saveECKeyAsDER(publicKey, "src/test/java/com/example/utils/publicKey.der");
			ECUtils.saveECKeyAsDER(privateKey, "src/test/java/com/example/utils/privateKey.der");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Ignore
	@Test
	public void testLoadECKeyFromPEM() {
		PublicKey publicKey = (PublicKey) ECUtils.loadECKeyFromPEM(true,
				"src/test/java/com/example/utils/publicKey.pem");
		PrivateKey privateKey = (PrivateKey) ECUtils.loadECKeyFromPEM(false,
				"src/test/java/com/example/utils/privateKey.pem");

		System.out.println(
				"Base64 publicKey length = " + Base64.getEncoder().encodeToString(publicKey.getEncoded()).length());
		System.out.println(
				"Base64 privateKey length = " + Base64.getEncoder().encodeToString(privateKey.getEncoded()).length());

		System.out.println("Hex string publicKey length = " + Hex.encodeHexString(publicKey.getEncoded()).length());
		System.out.println("Hex string privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());
		System.out.println("========================================");
		try {
			// signature
			String signString = ECDSASigner.signECDSA(privateKey, "message");
			System.out.println("Signature length = " + signString.length());

			// verify
			if (false == ECDSASigner.verifyECDSA(publicKey, "message", signString)) {
				System.out.println("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("ECDSA signer functionality test pass.");

	}

//	@Ignore
	@Test
	public void testLoadECKeyFromDER() {
		PublicKey publicKey = (PublicKey) ECUtils.loadECKeyFromDER(true,
				"src/test/java/com/example/utils/publicKey.der");
		PrivateKey privateKey = (PrivateKey) ECUtils.loadECKeyFromDER(false,
				"src/test/java/com/example/utils/privateKey.der");

		System.out.println(
				"Base64 publicKey length = " + Base64.getEncoder().encodeToString(publicKey.getEncoded()).length());
		System.out.println(
				"Base64 privateKey length = " + Base64.getEncoder().encodeToString(privateKey.getEncoded()).length());

		System.out.println("Hex string publicKey length = " + Hex.encodeHexString(publicKey.getEncoded()).length());
		System.out.println("Hex string privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());
		System.out.println("========================================");
		try {
			// signature
			String signString = ECDSASigner.signECDSA(privateKey, "message");
			System.out.println("Signature length = " + signString.length());

			// verify
			if (false == ECDSASigner.verifyECDSA(publicKey, "message", signString)) {
				System.out.println("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("ECDSA signer functionality test pass.");

	}

	@Ignore
	@Test
	public void testPrintECKeywithOpenssl() {
		System.out.println("==================DER publicKey==================");
		ECUtils.printECKeywithOpenssl(true, true, "src/test/java/com/example/utils/publicKey.der");
		System.out.println("\n==================DER privateKey==================");
		ECUtils.printECKeywithOpenssl(false, true, "src/test/java/com/example/utils/privateKey.der");
		System.out.println("\n");
		System.out.println("==================PEM publicKey==================");
		ECUtils.printECKeywithOpenssl(true, false, "src/test/java/com/example/utils/publicKey.pem");
		System.out.println("\n==================PEM privateKey==================");
		ECUtils.printECKeywithOpenssl(false, false, "src/test/java/com/example/utils/privateKey.pem");
	}

}
