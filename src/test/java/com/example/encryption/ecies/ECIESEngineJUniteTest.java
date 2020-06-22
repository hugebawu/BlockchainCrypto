/**
 * 
 */
package com.example.encryption.ecies;

import static org.junit.Assert.assertEquals;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

import cn.edu.ncepu.crypto.encryption.ecies.ECIESEngine;
import cn.edu.ncepu.crypto.utils.ECUtils;

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

//	@Ignore
	@Test
	public void testECIES_Encrypt_Eecrypt() {
		PublicKey publicKey = (PublicKey) ECUtils.loadECKeyFromPEM(true,
				"src/test/java/com/example/utils/publicKey.pem");
		PrivateKey privateKey = (PrivateKey) ECUtils.loadECKeyFromPEM(false,
				"src/test/java/com/example/utils/privateKey.pem");
		String content = "cryptography12342qer45taredfghdfghj/？！#@￥##%……";
		// encrypt the ciphertext can be transmitted directly through network.
		String ciphertext = ECIESEngine.encrypt(content, publicKey);
		System.out.println("plaintext: " + content);
		System.out.println("base64 ciphertext: " + ciphertext);
		System.out.println("base64 ciphertext length: " + ciphertext.length());
		// decrypt
		String decryptedtext = ECIESEngine.decrypt(ciphertext, privateKey);
		System.out.println("decrypted plaintext: " + decryptedtext);
		assertEquals(content, decryptedtext);
	}
}
