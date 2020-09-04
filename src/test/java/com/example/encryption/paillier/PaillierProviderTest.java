/**
 * 
 */
package com.example.encryption.paillier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.paillier.PaillierProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Sep 4, 2020 8:09:35 PM
 * @ClassName PaillierProviderTest
 * @Description: TODO(test encryption,decryption paillier JCA Provider and several properties including hommomorphism)
 */

@SuppressWarnings("restriction")
public class PaillierProviderTest {

	private static final String DELIMITER = "[,]";
	private static Logger logger = LoggerFactory.getLogger(PaillierProviderTest.class);

	@Test
	public void testEnc_Dec() throws Exception {

		// Add dynamically the desired provider
		Security.addProvider(new PaillierProvider());

		/////////////////////////////////////////////////////////////////////
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
		kpg.initialize(32);
		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey pubKey = keyPair.getPublic();
		PrivateKey privKey = keyPair.getPrivate();

		final Cipher cipher = Cipher.getInstance("Paillier");
		final Cipher cipherHP = Cipher.getInstance("PaillierHP");

		logger.info("The Paillier public key through Generator is \n" + keyPair.toString());
		System.err.println("The Paillier public key is \n" + keyPair.getPublic().toString());
		System.err.println("The Paillier private key is \n" + keyPair.getPrivate().toString());
		String plainText = "101";
		String plaintext1 = "101";
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

		// encrypt
		BigInteger codedBytes = encrypt(first.toByteArray(), pubKey, cipherHP);
		BigInteger codedBytes12 = encrypt(second.toByteArray(), pubKey, cipherHP);
		// product
		BigInteger product = codedBytes.multiply(codedBytes12);

		// product mod n^2
		BigInteger tallyProduct = product.mod(n2);
		System.err.println(" Product mod n^2:      " + tallyProduct);
		decrypt(tallyProduct.toByteArray(), privKey, cipherHP);

		decrypt(codedBytes.toByteArray(), privKey, cipherHP);
		decrypt(codedBytes12.toByteArray(), privKey, cipherHP);

		////////////////////////////// BLOCK EXAMPLE/////////////////////////////////
		String plainTextBlock = "This Provider working correctly and its safe 10000000000000000011000000000000000001";
		System.err.println("This is the message which will be encrypted: " + plainTextBlock);

		// encrypt
		byte[] codedBytesBlock = encryptBlock(plainTextBlock.getBytes(), pubKey, cipher);
		String codedMessageBlock = new String(codedBytesBlock);
		String codedMessageBlockInHEX = formatingHexRepresentation(codedBytesBlock);
		System.err.println("\n" + "ENCRYPTED :  \n" + codedMessageBlock);
		System.err.println("\n" + "ENCRYPTED in HEX:  \n" + codedMessageBlockInHEX);

		// decrypt
		byte[] encodedBytesBlock = decryptBlock(codedMessageBlock, privKey, cipher);
		String encodedMessageBlock = new String(encodedBytesBlock);
		System.err.println("\n" + "DECRYPTED:  \n" + encodedMessageBlock);
	}

	public byte[] encryptBlock(final byte[] text, final PublicKey key, final Cipher cipher) throws Exception {

		byte[] cipherText = null;

		System.err.println("\n" + "Provider encryption is: " + cipher.getProvider().getInfo());
		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text);
		final BASE64Encoder encoder = new BASE64Encoder();
		final String base64 = encoder.encode(cipherText);
		final byte[] encryptedBytes = base64.getBytes();

		return encryptedBytes;
	}

	public byte[] decryptBlock(final String text, final PrivateKey key, final Cipher cipher) throws Exception {

		byte[] dectyptedBytes = null;
		System.err.println("\n" + "Provider for decryption is: " + cipher.getProvider().getInfo());
		cipher.init(Cipher.DECRYPT_MODE, key);
		final BASE64Decoder decoder = new BASE64Decoder();
		final byte[] raw = decoder.decodeBuffer(text);
		dectyptedBytes = cipher.doFinal(raw);

		return dectyptedBytes;
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
			eye = byteToHex(codedBytes[i]);
			hexRepresentation += eye;
			if (i < codedBytes.length - 1) {
				hexRepresentation += ":";
			}
		}

		return hexRepresentation;
	}

	public BigInteger encrypt(final byte[] text, final PublicKey key, final Cipher cipher) throws Exception {

		byte[] cipherText = null;
		System.err.println("\n" + "Provider encryption is: " + cipher.getProvider().getInfo());

		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text);
		BigInteger result = new BigInteger(cipherText);
		System.err.println("BigInteger ciphertext: " + result);

		return result;
	}

	public BigInteger decrypt(final byte[] text, final PrivateKey key, final Cipher cipher) throws Exception {

		byte[] dectyptedBytes = null;
		System.out.println("\n" + "Provider for decryption is: " + cipher.getProvider().getInfo());
		cipher.init(Cipher.DECRYPT_MODE, key);
		dectyptedBytes = cipher.doFinal(text);
		BigInteger resultPlain = new BigInteger(dectyptedBytes);
		System.err.println("BigInteger plaintext: " + resultPlain);

		return resultPlain;
	}

	/**
	 * Convenience method to convert a byte to a hex string.
	 * 
	 * @param data the byte to convert
	 * @return String the converted byte
	 */
	public static String byteToHex(byte data) {

		StringBuffer buf = new StringBuffer();
		buf.append(toHexChar((data >>> 4) & 0x0F));
		buf.append(toHexChar(data & 0x0F));

		return buf.toString();
	}

	/**
	 * Convenience method to convert an int to a hex char.
	 * 
	 * @param i the int to convert
	 * @return char the converted char
	 */
	public static char toHexChar(int i) {

		if ((0 <= i) && (i <= 9)) {
			return (char) ('0' + i);
		} else {
			return (char) ('A' + (i - 10));
		}
	}
}
