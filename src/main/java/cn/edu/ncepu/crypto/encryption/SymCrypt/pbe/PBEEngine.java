/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.SymCrypt.pbe;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 24, 2020 8:43:53 PM
 * @ClassName PBEEngine
 * @Description:  (口令加密算法，password based encryption)
 */
public class PBEEngine {

	// example PBEWithMD5AndDES (PKCS #5, 1.5),
	// PBEWithHmacSHA256AndAES_128 (PKCS #5, 2.0)
	static String ALGORITHM_STRING_TEMP = "PBEWith<digest>And<encryption>";
	final static int ITERATIONCOUNT = 1000;

	/**
	 *   e.g., AES. hash to generate the real key for AES through the password and secure
	 * random salt, and then use it to encrypt or decrypt the input
	 * @param isEnc encryption or decryption
	 * @param digest_alg
	 * @param enc_alg
	 * @param password user password
	 * @param salt 16 bytes random salt. It can be store to USB flash disk to form the 
	 *        [USB key(with high secure random salt key)+password] encryption scheme.
	 * @param input
	 * @return 参数描述
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] enc_dec_PBE(boolean isEnc, String digest_alg, String enc_alg, String password, byte[] salt,
			byte[] input) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// add BouncyCastle as provider to Java.Security
		Security.addProvider(new BouncyCastleProvider());
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory sKeyFactory;
		String ALGORITHM_STRING = ALGORITHM_STRING_TEMP.replace("<digest>", digest_alg).replace("<encryption>",
				enc_alg);
		sKeyFactory = SecretKeyFactory.getInstance(ALGORITHM_STRING);
		SecretKey skey = sKeyFactory.generateSecret(keySpec);
		// bigger ITERATIONCOUNT, harder to crack
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, ITERATIONCOUNT);
		Cipher cipher = Cipher.getInstance(ALGORITHM_STRING);
		// generate the real 128/192/256 bit key.
		if (isEnc) {
			cipher.init(Cipher.ENCRYPT_MODE, skey, pbeParameterSpec);
		} else {
			cipher.init(Cipher.DECRYPT_MODE, skey, pbeParameterSpec);
		}
		return cipher.doFinal(input);
	}
}
