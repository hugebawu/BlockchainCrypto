/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.rsa;

import static org.junit.Assert.assertEquals;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 25, 2020 12:08:51 PM
 * @ClassName RSA
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
public class RSAEncEngine {
	private static final String RSA_STRING = "RSA";

	public static KeyPair getRSAKeyPair(int keysize) {
		// The valid key length should be the multiple of 1024 bits, default = 1024
		// bits, shorter than 1024 bits is not safe any more.
		assertEquals(0, keysize % 1024);
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_STRING);
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			// set key parameters
			keyPairGenerator.initialize(keysize, random);
			return keyPairGenerator.generateKeyPair();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @Description: TODO(这里用一句话描述这个方法的作用)
	 * @param content: content waits to be encrypted
	 * @param publickey: the other party's based64 encoded RSA public key
	 * @return 参数描述
	 * @throws
	 */
	public static byte[] encrypt(byte[] plaintext, String publickey) {
		try {
			// recover PublicKey from Base64 encoded public key
			// PublicKey is encoded according to X.509 protocol
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publickey));
			KeyFactory kf = KeyFactory.getInstance(RSA_STRING);
			RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(keySpec);
			// encrypt
			Cipher cipher = Cipher.getInstance(RSA_STRING);
			cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
			return cipher.doFinal(plaintext);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @Description: TODO(这里用一句话描述这个方法的作用)
	 * @param content: content waits to be encrypted
	 * @param publickey: the other party's based64 encoded RSA public key
	 * @return 参数描述
	 * @throws
	 */
	public static byte[] decrypt(byte[] ciphertext, String privatekey) {
		try {
			// recover PrivateKey from Base64 encoded public key
			// PublicKey is encoded according to X.509 protocol
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privatekey));
			KeyFactory kf = KeyFactory.getInstance(RSA_STRING);
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
			// encrypt
			Cipher cipher = Cipher.getInstance(RSA_STRING);
			cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
			return cipher.doFinal(ciphertext);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

}
