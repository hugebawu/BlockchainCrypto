/**
 * 
 */
package cn.edu.ncepu.crypto.keyExchange;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import cn.edu.ncepu.crypto.utils.CommonUtils;

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

	/**
	 * TODO get Diffie_Hellman algorithm key pair
	 * @param keysize
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static KeyPair getDHKeyPair(int keysize) throws NoSuchAlgorithmException {
		// The valid key length should be the multiple of 64 bits, default = 1024 bits.
		if (0 != keysize % 64) {
			throw new IllegalArgumentException(
					"valid key length should be the multiple of 64 bits, and minumum secure is 1024");
		}
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DH_STRING);
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		// set key parameters
		keyPairGenerator.initialize(keysize, random);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * TODO(generate shared key for ECDH key exchange scheme)
	 * @param publickey: the other party's based64 encoded Diffie-Hellman public key
	 * @param privateKey: own private key
	 * @return shared key string
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static String genSharedKey(PublicKey publickey, PrivateKey privatekey)
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_STRING);
		keyAgreement.init(privatekey);
		keyAgreement.doPhase(publickey, true);
		return Hex.encodeHexString(keyAgreement.generateSecret());
	}

	/**
	 * TODO(generate shared key for ECDH key exchange scheme)
	 * @param publickey: the other party's based64 encoded Diffie-Hellman public key
	 * @param privateKey: own private key
	 * @return shared key string
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws DecoderException 
	 * @throws InvalidKeySpecException 
	 */
	public static String genSharedKey(String publickey, PrivateKey privatekey)
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, DecoderException {
		KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_STRING);
		keyAgreement.init(privatekey);
		PublicKey publicKey = (PublicKey) CommonUtils.string2ECKey(true, "Base64", publickey, DH_STRING);
		keyAgreement.doPhase(publicKey, true);
		return Hex.encodeHexString(keyAgreement.generateSecret());
	}

	/**
	 * TODO(generate shared key from public and private String key)
	 * @param publicKey String
	 * @param PrivateKey String
	 * @return shared key string
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws DecoderException 
	 * @throws InvalidKeySpecException 
	 */
	public static String genSharedKey(String publicKey, String privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, DecoderException {
		return genSharedKey((PublicKey) CommonUtils.string2ECKey(true, "Base64", publicKey, DH_STRING),
				(PrivateKey) CommonUtils.string2ECKey(false, "Base64", privateKey, DH_STRING));
	}

}
