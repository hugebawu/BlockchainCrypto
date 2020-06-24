/**
 * 
 */
package cn.edu.ncepu.crypto.keyExchange;

import static org.junit.Assert.assertEquals;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyAgreement;

import org.apache.commons.codec.binary.Hex;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 24, 2020 11:34:06 PM
 * @ClassName DH
 * @Description: TODO(Diffie-Hellman shared key exchange methods)
 */
public class DH {
	private static final String DH_STRING = "DH";

	public static KeyPair getDHKeyPair(int keysize) {
		// The valid key length should be the multiple of 64 bits, default = 1024 bits.
		assertEquals(0, keysize % 64);
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DH_STRING);
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
	 * @Description: TODO(generate shared key from public and private String key)
	 * @param publicKey String
	 * @param PrivateKey String
	 * @return shared key string
	 * @throws
	 */
//	public static String genSharedKey(String publicKey, String privateKey) {
//		return genSharedKey((PublicKey) ECUtils.string2ECKey(true, publicKey),
//				(PrivateKey) ECUtils.string2ECKey(false, privateKey));
//	}

	/**
	 * @Description: TODO(generate shared key for ECDH key exchange scheme)
	 * @param publickey: the other party's based64 encoded Diffie-Hellman public key
	 * @param privateKey: own private key
	 * @return shared key string
	 * @throws
	 */
	public static String genSharedKey(String publickey, PrivateKey privateKey) {
		try {
			// recover PublicKey from Base64 encoded public key
			// PublicKey is encoded according to X.509 protocol
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publickey));
			KeyFactory kf = KeyFactory.getInstance(DH_STRING);
			PublicKey publicKey = kf.generatePublic(keySpec);
			KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_STRING);
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);
			return Hex.encodeHexString(keyAgreement.generateSecret());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
}
