/**
 * 
 */
package cn.edu.ncepu.crypto.signature.rsa;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

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
	 * TODO(sign the message with private key)
	 * @param privateKey
	 * @param message
	 * @return base64 encoded signature
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static byte[] signRSA(RSAPrivateKey rsaPrivateKey, byte[] message)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
		signature.initSign(rsaPrivateKey);
		// when the message is big, it can be divided into blocks(e,g, 1KB one time)
		signature.update(message);
		return signature.sign();
	}

	/**
	 * TODO(verify the RSA signature)
	 * @param publickey
	 * @param message
	 * @param singed
	 * @return ture or false
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static boolean verifyRSA(RSAPublicKey rsaPublicKey, byte[] message, byte[] singed)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
		signature.initVerify(rsaPublicKey);
		signature.update(message);
		return signature.verify(singed);
	}
}
