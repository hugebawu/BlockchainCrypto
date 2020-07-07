/**
 * 
 */
package cn.edu.ncepu.crypto.keyExchange;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
 * @CreateData: Jun 19, 2020 4:02:31 PM
 * @ClassName ECDH
 * @Description: TODO(elliptic curve based Diffie-Hellman secure key exchange algorithm)
 */
public class ECDH {
	private static final String EC_STRING = "EC";
	private static final String ECDH_STRING = "ECDH";

	/**
	 * TODO(generate shared key for ECDH key exchange scheme)
	 * @param publicKey the other party's EC public key
	 * @param privateKey own private key
	 * @return shared key string
	 * @throws NoSuchAlgorithmException 
	 * @throws IllegalStateException 
	 * @throws InvalidKeyException 
	 */
	public static String genSharedKey(PublicKey publicKey, PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {
		KeyAgreement keyAgreement;
		keyAgreement = KeyAgreement.getInstance(ECDH_STRING);
		keyAgreement.init(privateKey);
		keyAgreement.doPhase(publicKey, true);
		return Hex.encodeHexString(keyAgreement.generateSecret());
	}

	/**
	 * TODO(generate shared key from Hex public or private String key)
	 * @param publicKey String
	 * @param PrivateKey String
	 * @return shared key string
	 * @throws IllegalStateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws DecoderException 
	 * @throws InvalidKeySpecException 
	 */
	public static String genSharedKey(String publicKey, String privateKey) throws InvalidKeyException,
			NoSuchAlgorithmException, IllegalStateException, InvalidKeySpecException, DecoderException {
		return genSharedKey((PublicKey) CommonUtils.string2ECKey(true, "Hex", publicKey, EC_STRING),
				(PrivateKey) CommonUtils.string2ECKey(false, "Hex", privateKey, EC_STRING));
	}
}
