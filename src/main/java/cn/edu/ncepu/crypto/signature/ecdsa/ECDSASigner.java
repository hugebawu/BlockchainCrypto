package cn.edu.ncepu.crypto.signature.ecdsa;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.apache.commons.codec.binary.Hex;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 17, 2020 10:54:36 PM
 * @ClassName ECDSASigner
 * @Description: TODO(ecdsa signature scheme)
 */
/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 17, 2020 11:17:52 PM
 * @ClassName ECDSASigner
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
public class ECDSASigner {
	private static final String SCHEME_NAME = "Scott-Vanstone-1992 ecdsa signature scheme";
	private static final String SINGALGORITHM_STRING = "SHA256withECDSA";

	/**
	 * @Title: signECDSA
	 * @Description: TODO(sign the message with private key)
	 * @param privateKey
	 * @param message
	 * @return signed message
	 * @return String
	 * @throws
	 */
	public static String signECDSA(PrivateKey privateKey, String message) {
		String signString = "";
		try {
			Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
			signature.initSign(privateKey);
//			when the message is big, it can be divided into blocks(e,g, 1KB one time)
			signature.update(message.getBytes());
			/**
			 * 针对 SHA256withECDSA ，输出的是DER编码的签名数据，长度并非固定，但是是70到72字节，之所以会这样是因为，
			 * SHA256withECDSA 签名输出实际是两个32字节的大整数(r和s)，在转换成byte[]的时候，如果为负数，那么会添加前导位0，
			 * 如果当r和s都是正数，那么就是64个字节，都是负数，就是66字节。而DER编码还会包含类型以及长度字段，因此总长度就会到70到72字节。
			 * 一般情况下，传输DER编码的签名值没多大问题，但如果对数据量要求十分严格，例如在BLE上传输，可以提取出r和s再打包传输
			 */
			byte[] sign = signature.sign();
			signString = Hex.encodeHexString(sign);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return signString;
	}

	/**
	 * @Description: TODO(verify the ECDSA signature)
	 * @param publickey
	 * @param message
	 * @param singed
	 * @return ture or false
	 * @return boolean
	 * @throws
	 */
	public static boolean verifyECDSA(PublicKey publicKey, String message, String singed) {
		try {
			Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
			signature.initVerify(publicKey);
			signature.update(message.getBytes());
			byte[] sign = Hex.decodeHex(singed);
			return signature.verify(sign);
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return false;
	}

}
