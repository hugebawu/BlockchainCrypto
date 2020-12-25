/**
 * 
 */
package com.example.homomorphicencryption.paillier;

import cn.edu.ncepu.crypto.homomorphicEncryption.paillier.PaillierEngine;
import cn.edu.ncepu.crypto.homomorphicEncryption.paillier.PaillierPrivateKey;
import cn.edu.ncepu.crypto.homomorphicEncryption.paillier.PaillierProvider;
import cn.edu.ncepu.crypto.homomorphicEncryption.paillier.PaillierPublicKey;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import static org.junit.Assert.assertTrue;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Sep 4, 2020 8:09:35 PM
 * @ClassName PaillierProviderTest
 * @Description:  (test encryption,decryption paillier JCA Provider and several properties including hommomorphism)
 */

public class PaillierProviderTest {

	private static final String DELIMITER = "[,]";
	private static final Logger logger = LoggerFactory.getLogger(PaillierProviderTest.class);
	private static final PaillierEngine engine = PaillierEngine.getInstance();

	/**
	 * Verify for every m1,m2属于Zn, D( E(m1)E(m2) mod n^2)= m1+m2 mod n
	 * @throws Exception 参数描述
	 */
	@Ignore
	@Test
	public void testHomomorphism1() throws Exception {

		// Add dynamically the desired provider
		Security.addProvider(new PaillierProvider());

		/////////////////////////////////////////////////////////////////////
		// keyGen
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
		kpg.initialize(32);
		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey pubKey = keyPair.getPublic();
		PrivateKey privKey = keyPair.getPrivate();

		logger.info("The Paillier public key is: " + pubKey.toString());
		logger.info("The Paillier private key is: " + privKey.toString());
		String plainText = "101";
		String plaintext1 = "102";
		// get the n
		String[] keyComponents = pubKey.toString().split(DELIMITER);
		String keyComponent = "";
		for (String component : keyComponents) {
			if (component.startsWith("n")) {
				keyComponent = component.substring(2);// ignoring 'n:' or 'r:'
			}
		}
		BigInteger n = new BigInteger(keyComponent);
		BigInteger first = new BigInteger(plainText);
		BigInteger second = new BigInteger(plaintext1);
		BigInteger n2 = n.multiply(n);

		final Cipher cipherHP = Cipher.getInstance("PaillierHP");
		// encrypt
		logger.info("\n" + "Provider for encryption is: " + cipherHP.getProvider().getInfo());
		BigInteger codedBytes = engine.encrypt(first.toByteArray(), pubKey, cipherHP);
		logger.info("BigInteger ciphertext: " + codedBytes);

		BigInteger codedBytes12 = engine.encrypt(second.toByteArray(), pubKey, cipherHP);
		logger.info("BigInteger ciphertext: " + codedBytes12);

		// decrypt
		BigInteger resultPlain1 = engine.decrypt(codedBytes.toByteArray(), privKey, cipherHP);
		logger.info("BigInteger resultPlain: " + resultPlain1);

		BigInteger resultPlain2 = engine.decrypt(codedBytes12.toByteArray(), privKey, cipherHP);
		logger.info("BigInteger resultPlain: " + resultPlain2);

		// product
		BigInteger product = codedBytes.multiply(codedBytes12);

		// product mod n^2
		BigInteger tallyProduct = product.mod(n2);
		logger.info(" Product mod n^2:      " + tallyProduct);

		logger.info("\n" + "Provider for decryption is: " + cipherHP.getProvider().getInfo());
		BigInteger resultPlain = engine.decrypt(tallyProduct.toByteArray(), privKey, cipherHP);
		logger.info("BigInteger resultPlain: " + resultPlain);

		// verify homomorphism
		assertTrue(resultPlain.equals(resultPlain1.add(resultPlain2).mod(n)));
	}

	/**
	 * Verify for every m belong to Zn, D( E(m)^k mod n^2)= km mod n
	 * @throws Exception 参数描述
	 */
	@Ignore
	@Test
	public void testHomomorphism2() throws Exception {
		// Add dynamically the desired provider
		Security.addProvider(new PaillierProvider());

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
		kpg.initialize(32);
		KeyPair keyPair = kpg.generateKeyPair();
		PaillierPublicKey pubKey = (PaillierPublicKey) keyPair.getPublic();
		PaillierPrivateKey privKey = (PaillierPrivateKey) keyPair.getPrivate();
		final Cipher cipherHP = Cipher.getInstance("PaillierHP");

		BigInteger m = new BigInteger("101");
		// get the n
		BigInteger n = pubKey.getN();
		BigInteger nSquare = pubKey.getNSquare();

		// encrypt
		BigInteger encrypted_m = engine.encrypt(m.toByteArray(), pubKey, cipherHP);

		BigInteger k = new BigInteger("56756756765");
		BigInteger km = k.multiply(m).mod(n);

		// decrypt
		BigInteger resultPlain = engine.decrypt(encrypted_m.modPow(k, nSquare).toByteArray(), privKey, cipherHP);
		logger.info("BigInteger resultPlain: " + resultPlain);

		// verify homomorphism
		assertTrue(resultPlain.equals(km.mod(n)));
	}

	/**
	 * Verify for every m1,m2 belong to Zn, D( E(m1)^m2 mod n^2)= m1m2 mod n
	 * @throws Exception 参数描述
	 */
	@Ignore
	@Test
	public void testHomomorphism3() throws Exception {
		// Add dynamically the desired provider
		Security.addProvider(new PaillierProvider());

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
		kpg.initialize(32);
		KeyPair keyPair = kpg.generateKeyPair();
		PaillierPublicKey pubKey = (PaillierPublicKey) keyPair.getPublic();
		PaillierPrivateKey privKey = (PaillierPrivateKey) keyPair.getPrivate();
		final Cipher cipherHP = Cipher.getInstance("PaillierHP");

		BigInteger m1 = new BigInteger("101");
		BigInteger m2 = new BigInteger("3");
		// get the n
		BigInteger n = pubKey.getN();
		BigInteger nSquare = pubKey.getNSquare();

		// encrypt
		BigInteger encrypted_m1 = engine.encrypt(m1.toByteArray(), pubKey, cipherHP);

		// decrypt
		BigInteger resultPlain = engine.decrypt(encrypted_m1.modPow(m2, nSquare).toByteArray(), privKey, cipherHP);
		logger.info("BigInteger resultPlain: " + resultPlain);

		// verify homomorphism
		assertTrue(resultPlain.equals(m1.multiply(m2).mod(n)));
	}

	@Ignore
	@Test
	public void testBlockEncryption() throws Exception {
		// Add dynamically the desired provider
		Security.addProvider(new PaillierProvider());
		/////////////////////////////////////////////////////////////////////
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
		kpg.initialize(32);
		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey pubKey = keyPair.getPublic();
		PrivateKey privKey = keyPair.getPrivate();

		final Cipher cipher = Cipher.getInstance("Paillier");

		////////////////////////////// BLOCK EXAMPLE/////////////////////////////////
		String plainTextBlock = "This Provider working correctly and its safe 10000000000000000011000000000000000001";
		logger.info("This is the message which will be encrypted: " + plainTextBlock);

		// encrypt
		logger.info("Provider for encryption is: " + cipher.getProvider().getInfo());
		byte[] codedBytesBlock = engine.encryptBlock(plainTextBlock.getBytes(), pubKey, cipher);
		String codedMessageBlock = new String(codedBytesBlock, StandardCharsets.UTF_8);
		String codedMessageBlockInHEX = formatingHexRepresentation(codedBytesBlock);
		logger.info("ENCRYPTED :  \n" + codedMessageBlock + "\n");
		logger.info("ENCRYPTED in HEX:  \n" + codedMessageBlockInHEX + "\n");

		// decrypt
		logger.info("\n" + "Provider for decryption is: " + cipher.getProvider().getInfo());
		byte[] encodedBytesBlock = engine.decryptBlock(codedMessageBlock, privKey, cipher);
		String encodedMessageBlock = new String(encodedBytesBlock);
		logger.info("DECRYPTED:  \n" + encodedMessageBlock);
	}

	/**
	 * Convert byte[] to HEX by invoking the byteToHex() and after that splitting
	 * every two symbols with ':'
	 * 
	 * @param codedBytes
	 * @return String in Hex form with ":" between every two symbols
	 */
	public static String formatingHexRepresentation(final byte[] codedBytes) {
		String hexRepresentation = "";
		String eye;
		for (int i = 0; i < codedBytes.length; i++) {
			eye = CommonUtils.byteToHex(codedBytes[i]);
			hexRepresentation += eye;
			if (i < codedBytes.length - 1) {
				hexRepresentation += ":";
			}
		}
		return hexRepresentation;
	}
}
