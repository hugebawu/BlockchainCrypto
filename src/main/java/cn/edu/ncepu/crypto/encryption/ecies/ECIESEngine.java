/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.ecies;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 19, 2020 4:08:16 PM
 * @ClassName ECIESEngine
 * @Description: TODO(Utilize BouncyCastls to realize elliptic curve based Integrated Encryption Engine)
 * @Description The ECC was firstly proposed by Neal Koblitz and Victor Miller in 1985 separately.
 */
public class ECIESEngine {

	/**
	 * @Description: TODO(encrypt content as ecies using EC publicKey)
	 * @param content content waits to be encrypted
	 * @param publicKey EC publicKey
	 * @return Based64 coded ciphertext to convenient network transmission.
	 * @throws
	 */
	public static String encrypt(String content, PublicKey publicKey) {
		String cipherString = null;
		try {
			BouncyCastleProvider bcProvider = new BouncyCastleProvider();
			Cipher cipher = Cipher.getInstance("ECIES", bcProvider);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] ciphertext = cipher.doFinal(content.getBytes());
			// for transmission encode cipherText as Base64
			cipherString = Base64.getEncoder().encodeToString(ciphertext);
		} catch (NoSuchAlgorithmException e) {
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
		return cipherString;
	}

	/**
	 * @Description: TODO(decrypt cyphertext as ecies using EC privateKey)
	 * @param ciphertext ciphertext waits to be encrypted
	 * @param privateKey EC privateKey
	 * @return original plaintext string.
	 * @throws
	 */
	public static String decrypt(String ciphertext, PrivateKey privateKey) {
		String plaintext = null;
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		try {
			Cipher cipher = Cipher.getInstance("ECIES", bcProvider);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			plaintext = new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
		} catch (NoSuchAlgorithmException e) {
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
		return plaintext;
	}
}
