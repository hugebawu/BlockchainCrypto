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

import cn.edu.ncepu.crypto.algebra.Engine;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 19, 2020 4:08:16 PM
 * @ClassName ECIESEngine
 * @Description:  (Utilize BouncyCastls to realize elliptic curve based Integrated Encryption Engine)
 * @Description The ECC was firstly proposed by Neal Koblitz and Victor Miller in 1985 separately.
 */
public class ECIESEngine extends Engine {

	private static final String SCHEME_NAME = "elliptic curve based Integrated Encryption";
	private static ECIESEngine engine;

	public static ECIESEngine getInstance() {
		if (engine == null) {
			engine = new ECIESEngine();
		}
		return engine;
	}

	/**
	 * @param schemeName
	 * @param proveSecModel
	 * @param payloadSecLevel
	 * @param predicateSecLevel
	 */
	public ECIESEngine() {
		super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.ANON);
	}

	/**
	 *   encrypt content as ecies using EC publicKey
	 * @param content content waits to be encrypted
	 * @param publicKey EC publicKey
	 * @return Based64 coded ciphertext to convenient network transmission.
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 */
	public byte[] encrypt(byte[] content, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		Cipher cipher = Cipher.getInstance("ECIES", bcProvider);
//		EccUtils.setFieldValueByFieldName(cipher);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] ciphertext = cipher.doFinal(content);
		return ciphertext;
	}

	/**
	 *   decrypt cyphertext as ecies using EC privateKey
	 * @param ciphertext ciphertext waits to be encrypted
	 * @param privateKey EC privateKey
	 * @return original plaintext string.
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public byte[] decrypt(String ciphertext, PrivateKey privateKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		// ciphertext是采用base64编码后的内容，方便用于传输，下面会解码为byte[]类型的值
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		Cipher cipher = Cipher.getInstance("ECIES", bcProvider);
//		EccUtils.setFieldValueByFieldName(cipher);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(Base64.getDecoder().decode(ciphertext));
	}
}
