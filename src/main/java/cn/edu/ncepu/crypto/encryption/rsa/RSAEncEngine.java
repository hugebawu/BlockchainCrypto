/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.rsa;

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
 * @Description:  (RSA encryption scheme)
 */
public class RSAEncEngine {
	private static final String RSA_STRING = "RSA";

	/**
	 *   这里描述这个方法的作用
	 * @param keysize
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair getRSAKeyPair(int keysize) throws NoSuchAlgorithmException {
		// The valid key length should be the multiple of 1024 bits, default = 1024
		// bits, shorter than 1024 bits is not safe any more.
		if (0 != keysize % 1024) {
			throw new IllegalArgumentException("keysize is illegal");
		}
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_STRING);
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		// set key parameters
		keyPairGenerator.initialize(keysize, random);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 *  (这里用一句话描述这个方法的作用)
	 * @param content: content waits to be encrypted
	 * @param publickey: the other party's based64 encoded RSA public key
	 * @return 参数描述
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] encrypt(byte[] plaintext, String publickey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// recover PublicKey from Base64 encoded public key
		// PublicKey is encoded according to X.509 protocol
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publickey));
		KeyFactory kf = KeyFactory.getInstance(RSA_STRING);
		RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(keySpec);
		// encrypt
		Cipher cipher = Cipher.getInstance(RSA_STRING);
		cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
		return cipher.doFinal(plaintext);
	}

	/**
	 *  (这里用一句话描述这个方法的作用)
	 * @param content: content waits to be encrypted
	 * @param publickey: the other party's based64 encoded RSA public key
	 * @return 参数描述
	 */
	/**
	 *   这里描述这个方法的作用
	 * @param ciphertext
	 * @param privatekey
	 * @return 参数描述
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] decrypt(byte[] ciphertext, String privatekey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// recover PrivateKey from Base64 encoded public key
		// PublicKey is encoded according to X.509 protocol
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privatekey));
		KeyFactory kf = KeyFactory.getInstance(RSA_STRING);
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
		// encrypt
		Cipher cipher = Cipher.getInstance(RSA_STRING);
		cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
		return cipher.doFinal(ciphertext);
	}

}
