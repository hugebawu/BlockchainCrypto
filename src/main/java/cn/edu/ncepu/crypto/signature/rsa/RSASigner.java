/**
 * 
 */
package cn.edu.ncepu.crypto.signature.rsa;

import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 25, 2020 2:19:06 PM
 * @ClassName RSASigner
 * @Description: TODO(sign and verify the hash of message with RSA)
 */
public class RSASigner {
	// e.g., MD5withRSA, SHA1withRSA, SHA256withRSA
	private static final String SINGALGORITHM_STRING = "SHA256withRSA";

	/**
	 * @Title: signRSA
	 * @Description: TODO(sign the message with private key)
	 * @param privateKey
	 * @param message
	 * @return base64 encoded signature
	 * @throws
	 */
	public static String signRSA(RSAPrivateKey rsaPrivateKey, String message) {
		try {
			Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
			signature.initSign(rsaPrivateKey);
//			when the message is big, it can be divided into blocks(e,g, 1KB one time)
			signature.update(message.getBytes("UTF-8"));
			byte[] sign = signature.sign();
			return Base64.getEncoder().encodeToString(sign);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @Description: TODO(verify the RSA signature)
	 * @param publickey
	 * @param message
	 * @param singed
	 * @return ture or false
	 * @throws
	 */
	public static boolean verifyRSA(RSAPublicKey rsaPublicKey, String message, String singed) {
		try {
			Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
			signature.initVerify(rsaPublicKey);
			signature.update(message.getBytes("UTF-8"));
			byte[] sign = Base64.getDecoder().decode(singed);
			return signature.verify(sign);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
}
