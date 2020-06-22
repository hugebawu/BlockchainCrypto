/**
 * 
 */
package cn.edu.ncepu.crypto.keyExchange;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;

import org.apache.commons.codec.binary.Hex;

import cn.edu.ncepu.crypto.utils.ECUtils;

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
	 * @Description: TODO(generate shared key from public and private String key)
	 * @param publicKey String
	 * @param PrivateKey String
	 * @return shared key string
	 * @throws
	 */
	public static String genSharedKey(String publicKey, String privateKey) {
		return genSharedKey((PublicKey) ECUtils.string2ECKey(true, publicKey),
				(PrivateKey) ECUtils.string2ECKey(false, privateKey));
	}

	/**
	 * @Description: TODO(generate shared key for ECDH key exchange scheme)
	 * @param publicKey
	 * @param privateKey
	 * @return shared key string
	 * @throws
	 */
	public static String genSharedKey(PublicKey publicKey, PrivateKey privateKey) {
		String sharedKeyString = "";
		KeyAgreement keyAgreement;
		try {
			keyAgreement = KeyAgreement.getInstance(ECDH_STRING);
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);
			sharedKeyString = Hex.encodeHexString(keyAgreement.generateSecret());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return sharedKeyString;
	}
}
