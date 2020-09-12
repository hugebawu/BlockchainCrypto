/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.paillier;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

import cn.edu.ncepu.crypto.algebra.Engine;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Sep 6, 2020 11:19:55 AM
 * @ClassName PaillierEngine
 * @Description:  (paillier cryptosystems was formally defined and constructed in 1999)
 */
public class PaillierEngine extends Engine {
	// Scheme name, used for exceptions
	private static final String SCHEME_NAME = "Paillier 1999";
	private static PaillierEngine engine;

	public static PaillierEngine getInstance() {
		if (null == engine) {
			engine = new PaillierEngine(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA,
					PredicateSecLevel.ANON);
		}
		return engine;
	}

	/**
	 * @param schemeName
	 * @param proveSecModel
	 * @param payloadSecLevel
	 * @param predicateSecLevel
	 */
	public PaillierEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel,
			PredicateSecLevel predicateSecLevel) {
		super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
	}

	/**
	 * Encryption algorithm for Paillier
	 * @param text
	 * @param key
	 * @param cipher
	 * @return
	 * @throws Exception 参数描述
	 */
	public BigInteger encrypt(final byte[] text, final PublicKey key, final Cipher cipher) throws Exception {

		byte[] cipherText = null;

		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text);
		BigInteger result = new BigInteger(cipherText);

		return result;
	}

	/**
	 * Decryption algorithm for Paillier
	 * @param text
	 * @param key
	 * @param cipher
	 * @return
	 * @throws Exception 参数描述
	 */
	public BigInteger decrypt(final byte[] text, final PrivateKey key, final Cipher cipher) throws Exception {
		byte[] dectyptedBytes = null;
		cipher.init(Cipher.DECRYPT_MODE, key);
		dectyptedBytes = cipher.doFinal(text);
		BigInteger resultPlain = new BigInteger(dectyptedBytes);
		return resultPlain;
	}

	public byte[] encryptBlock(final byte[] text, final PublicKey key, final Cipher cipher) throws Exception {
		byte[] cipherText = null;
		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text);
		final String base64 = Base64.getEncoder().encodeToString(cipherText);
		final byte[] encryptedBytes = base64.getBytes("UTF-8");
		return encryptedBytes;
	}

	public byte[] decryptBlock(final String text, final PrivateKey key, final Cipher cipher) throws Exception {
		byte[] dectyptedBytes = null;
		cipher.init(Cipher.DECRYPT_MODE, key);
		final byte[] raw = Base64.getDecoder().decode(text);
		dectyptedBytes = cipher.doFinal(raw);
		return dectyptedBytes;
	}

	public String getEngineName() {
		return SCHEME_NAME;
	}
}
