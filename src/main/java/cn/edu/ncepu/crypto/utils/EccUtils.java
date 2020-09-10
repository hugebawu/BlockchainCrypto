/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 26, 2020 10:11:39 PM
 * @ClassName EccUtils
 * @Description: 1.解决了一部分jre环境由于美国出口限制，导致密钥长度不能超过128，此时可以利用反射对java对象进行修改，使得256位的密钥长度也能通过。
 * （当然自己也可以替换jre环境的jar包，具体jar包可以去网上查找异常的解决方案）。
 * 2.私钥和公钥可以使用Base'64进行编码，后用来传输。到其他服务使用时，可以将Base64字符串转成相应的私钥和公钥对象。
 */
@SuppressWarnings("unused")
public class EccUtils {
	// 密钥长度
	private final static int KEY_SIZE = 256;
	private final static String SIGNATURE_ALGORITHM = "SHA256withECDSA";
	// 注册BouncyCastle加密包
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 输出BouncyCastleProvider支持的算法，其中就有支持ECC加密的算法
	 */
	private static void printProvider() {
		Provider provider = new BouncyCastleProvider();
		for (Provider.Service service : provider.getServices()) {
			System.out.println(service.getType() + ":" + service.getAlgorithm());
		}
	}

	/**
	 * 生成密钥对
	 * @return
	 * @throws Exception
	 */
	public static KeyPair getKeyPair(int keySize) throws Exception {
		// BC即BouncyCastle加密包，EC为ECC算法
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
		keyPairGenerator.initialize(keySize, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	/**
	 * 获取公钥（BASE64编码成字符串后方便用于其他人解码）
	 * @param keyPair
	 * @return
	 */
	public static String publicKey2String(ECPublicKey publicKey) {
		byte[] bytes = publicKey.getEncoded();
		return Base64.getEncoder().encodeToString(bytes);
	}

	/**
	* 获取私钥（Base64编码）
	* @param keyPair
	* @return
	*/
	public static String privateKey2String(ECPrivateKey privateKey) {
		byte[] bytes = privateKey.getEncoded();
		return Base64.getEncoder().encodeToString(bytes);
	}

	/**
	 * 公钥加密
	 * @param content
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] content, ECPublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		// setFieldValueByFieldName(cipher);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(content);
	}

	/**
	 * 私钥解密
	 * @param content
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(String content, ECPrivateKey privateKey) throws Exception {
		// content是采用base64编码后的内容，方便用于传输，下面会解码为byte[]类型的值
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		// setFieldValueByFieldName(cipher);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(Base64.getDecoder().decode(content));
	}

	/**
	 * 使用反射解决因美国出口限制，ECC算法的密钥长度不能超过128的问题,如果需要的话，可以加
	 * @param object
	 */
	public static void setFieldValueByFieldName(Cipher object) {
		if (object == null) {
			return;
		}
		// 获取Obj类的字节文件对像
		Class<? extends Cipher> cipher = object.getClass();
		try {
			// 获取该类的成员变量CryptoPermission cryptoPerm;
			Field cipherField = cipher.getDeclaredField("cryptoPerm");
			cipherField.setAccessible(true);
			Object cryptoPerm = cipherField.get(object);

			// 获取CryptoPermission类的成员变量maxKeySize
			Class<? extends Object> c = cryptoPerm.getClass();

			Field[] cs = c.getDeclaredFields();
			Field cryptoPermField = c.getDeclaredField("maxKeySize");
			cryptoPermField.setAccessible(true);
			// 设置maxKeySize的值为257，257>256
			cryptoPermField.set(cryptoPerm, 257);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 私钥签名
	 * @param content
	 * @param privateKey
	 * @return
	 */
	public static byte[] sign(String content, ECPrivateKey privateKey) throws Exception {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);
		signature.update(content.getBytes());
		return signature.sign();
	}

	/**
	 * 公钥验签
	 * @param content
	 * @param sign
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(String content, byte[] sign, ECPublicKey publicKey) throws Exception {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);
		signature.update(content.getBytes());
		return signature.verify(sign);
	}

	/**
	* 解析证书的签名算法，单独一本公钥或者私钥是无法解析的，证书的内容远不止公钥或者私钥
	* @param certFile
	* @return
	* @throws Exception
	*/
	private static String getSignature(File certFile) throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate x509Certificate = (X509Certificate) certificateFactory
				.generateCertificate(new FileInputStream(certFile));
		return x509Certificate.getSigAlgName();
	}

	/**
	 * 将Base64编码后的公钥转换成PublicKey对象，Base64编码后的公钥可以用于网络传输
	 * @param pubStr
	 * @return
	 * @throws Exception
	 */
	public static ECPublicKey string2PublicKey(String pubStr) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(pubStr);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
		ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	/**
	 * 将Base64编码后的私钥转换成PrivateKey对象，Base64编码后的私钥可以用于网络传输
	 * @param priStr
	 * @return
	 * @throws Exception
	 */
	public static ECPrivateKey string2PrivateKey(String priStr) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(priStr);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
		ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);
		return privateKey;
	}

	/**
	 * TODO(print the content of DER or PEM ECKey file)
	 * @param isECPublicKey
	 * @param isDER
	 * @param pathName pathName for the DER or PEM, and PublicKey or PrivateKey file
	 * @throws Exception 
	 */
	public static void printECKeywithOpenssl(boolean isECPublicKey, boolean isDER, String pathName) throws Exception {
		int indexofSlash = pathName.lastIndexOf("/");
		String filePath = pathName.substring(0, indexofSlash);
		String fileName = pathName.substring(indexofSlash + 1, pathName.length());
		String shell = "";
		if (isECPublicKey) {
			if (isDER) {
				shell = "openssl pkey -inform DER -pubin -in " + fileName + " -text";
			} else {
				shell = "openssl ec -in " + fileName + " -pubin -text -noout";
			}
		} else {
			if (isDER) {
				shell = "openssl pkey -inform DER -in " + fileName + " -text";
			} else {
				shell = "openssl ec -in " + fileName + " -text -noout";
			}
		}
		CommonUtils.callCMD(shell, filePath);
	}

}
