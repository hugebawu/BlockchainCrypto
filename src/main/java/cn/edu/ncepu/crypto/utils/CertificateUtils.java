/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 25, 2020 3:02:06 PM
 * @ClassName CertificateUtils
 * @Description:  (utilize certificate to realize the function of
 * digital signature, identity authentication, data encryption and decryption)
 */
public class CertificateUtils {

	public final static String X509 = "X.509";

	/**
	 * 密钥库枚举
	 * 
	 *JKS，Java Key Store。可以参见sun.security.provider.JavaKeyStore类，此密钥库是特定于Java平台的，通常具有jks的扩展名。此类型的密钥库可以包含私钥和证书，但不能用于存储密钥。由于它是Java特定的密钥库，因此不能在其他编程语言中使用。存储在JKS中的私钥无法在Java中提取。
	 *目前，Java中的默认密钥库类型是JKS，即如果在使用keytool创建密钥库时未指定-storetype，则密钥库格式将为JKS。但是，默认密钥库类型将在Java 9中更改为PKCS12，因为与JKS相比，它具有增强的兼容性。可以在$ JRE / lib / security / java.security文件中检查默认密钥库类型。
	 *JCEKS，JCE密钥库（Java Cryptography Extension KeyStore）。可以认为是增强式的JKS密钥库，支持更多算法。可以参考com.sun.crypto.provider.JceKeyStore类，此密钥库具有jceks的扩展名。可以放入JCEKS密钥库的条目是私钥，密钥和证书。此密钥库通过使用Triple DES加密为存储的私钥提供更强大的保护。
	 *JCEKS的提供者是SunJCE，它是在Java 1.4中引入的。因此，在Java 1.4之前，只能使用JKS。
	 *PKCS11，一种硬件密钥库类型。 为Java库提供了一个接口，用于连接硬件密钥库设备，如智能卡。 可以参考sun.security.pkcs11.P11KeyStore类。  此密钥库可以存储私钥，密钥和证书。 加载密钥库时，将从密钥库中检索条目，然后将其转换为软件成勋可识别的条目；
	 *PKCS12，一种标准的密钥库类型，可以在Java和其他语言中使用。可以参考sun.security.pkcs12.PKCS12KeyStore类。它通常具有p12或pfx的扩展名。可以在此类型上存储私钥，密钥和证书。与JKS不同，PKCS12密钥库上的私钥可以用Java提取。此类型是可以与其他语言（如C，C ++或C＃）编写的其他库一起使用。
	 *BKS，BoucyCastle密钥库，是一种密钥库格式，提供了流行的第三方Java加密库提供程序–BouncyCastle。它是一个类似于Oracle JDK提供的JKS的密钥库。支持存储密钥，私钥和证书，经常用于移动应用程序开发。
	 */
	public static enum JKeyStoreType {

		JCEKS, JKS, DKS, PKCS11, PKCS12;

		public String getName() {
			return this.name();
		}
	}

	/**
	 *  (generate key store file, 一个密钥库可以包含多个证书及其对应的公或私钥)
	 * @param storepass keystore password
	 * @param keyalg encryption algorithm e.g., RSA；
	 * @param keysize size of the key
	 * @param sigalg signature algorithm e.g., SHA1withRSA；
	 * @param validity validity days of the certificate；
	 * @param alias alias of keystore
	 * @param dname Unique distinguished name(CN: common name, if the certificateis used https,it should be the same as domain name)
	 * @return
	 * @throws Exception 
	 */
	public static void exportKeyStore(String alias) throws Exception {
		String[] arrCommand = new String[] { "keytool", "-genkey", // -genkey表示生成密钥
				"-alias", alias, // -alias指定别名，这里是mykeystore
				"-validity", "3650", // -validity指定证书有效期(单位：天)，这里是36000天
				"-keysize", "1024", // 指定密钥长度
				"-keyalg", "RSA", // -keyalg 指定密钥的算法 (如 RSA DSA（如果不指定默认采用DSA）)
				"-keystore", SysProperty.USER_DIR + "/elements/my.keystore", // -keystore指定存储位置，这里是/root/Documents/eclipse-workspace/BlockchainCrypto/elements/my.keystore
				"-dname", "CN=(www.ncepu.edu.cn), OU=(CCE), O=(NCEPU), L=(BJ), ST=(BJ), C=(CN)",
				// CN=(名字与姓氏),OU=(组织单位名称), O=(组织名称),L=(城市或区域名称),ST=(州或省份名称), C=(单位的两字母国家代码)"
				"-storepass", "123456", // 指定密钥库的密码(获取keystore信息所需的密码)
				"-keypass", "123456", // 指定别名条目的密码(私钥的密码)
				"-v" // 详细输出
		};
//		for (int i = 0; i < arrCommand.length; i++) {
//			System.out.print(arrCommand[i] + " ");
//		}
//		logger.info();
		CommonUtils.callCMD(arrCommand, null);
	}

	/**
	 *  (export certificate file from key store)
	 * @param storepass keystore password
	 * @param alias the name of certificate in programme；
	 * @param keystore name of the keystore
	 * @param rfc output in the form of RFC
	 * @throws Exception 
	 */
	public static void exportCer(String alias) throws Exception {
		String[] arrCommand = new String[] { "keytool", "-export", // - export指定为导出操作
				"-keystore", SysProperty.USER_DIR + "/elements/my.keystore", // -keystore指定keystore文件，这里是/root/Documents/eclipse-workspace/BlockchainCrypto/elements/my.keystore
				"-alias", alias, // -alias指定别名，这里是mykeystore
				"-file", SysProperty.USER_DIR + "/elements/my.cer", // -file指向导出路径
				"-storepass", "123456", // 指定密钥库的密码
				"-rfc", // 以RFC样式输出
				"-v"// -v 显示证书详细信息
		};
//		for (int i = 0; i < arrCommand.length; i++) {
//			System.out.print(arrCommand[i] + " ");
//		}
//		logger.info();
		CommonUtils.callCMD(arrCommand, null);
	}

	/**
	 * 获得{@link KeyStore}
	 * 
	 * @param in
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static KeyStore getKeyStore(InputStream in, char[] password, JKeyStoreType keyStore)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		return getKeyStore(in, password, keyStore.getName());
	}

	/**
	 * 获得{@link KeyStore}
	 * 
	 * @param in
	 * @param password
	 * @param keyStoreType
	 * @return
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws Exception
	 */
	public static KeyStore getKeyStore(InputStream in, char[] password, String keyStoreType)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance(keyStoreType);
		ks.load(in, password);
		return ks;
	}

	/**
	 * 列出别名
	 * 
	 * @param keyStore
	 * @return
	 * @throws KeyStoreException 
	 */
	public static List<String> listAlias(KeyStore keyStore) throws KeyStoreException {
		Enumeration<String> aliasEnum = keyStore.aliases();
		List<String> aliases = new ArrayList<String>();
		while (aliasEnum.hasMoreElements()) {
			aliases.add(aliasEnum.nextElement());
		}
		return aliases;
	}

	/**
	 * 获得私钥{@link PrivateKey}
	 * 
	 * @param keyStore
	 * @param alias
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static PrivateKey getPrivateKey(KeyStore keyStore, String alias, char[] password)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		PrivateKey key = (PrivateKey) keyStore.getKey(alias, password);
		return key;
	}

	/**
	 * 获得私钥{@link PrivateKey}
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static PrivateKey getPrivateKey(InputStream in, String alias, char[] password, JKeyStoreType keyStore)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException {
		return getPrivateKey(in, alias, password, keyStore.getName());
	}

	/**
	 * 获得私钥{@link PrivateKey}
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(InputStream in, String alias, char[] password, String keyStoreType)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException {
		KeyStore ks = getKeyStore(in, password, keyStoreType);
		PrivateKey key = (PrivateKey) ks.getKey(alias, password);
		return key;
	}

	/**
	 * 获得{@link Certificate}
	 * 
	 * @param in
	 * @return
	 * @throws CertificateException 
	 */
	public static Certificate getCertificate(InputStream in) throws CertificateException {
		CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
		Certificate certificate = certificateFactory.generateCertificate(in);
		return certificate;
	}

	/**
	 * 获得{@link Certificate}
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static Certificate getCertificate(InputStream in, String alias, char[] password, JKeyStoreType keyStore)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		return getCertificate(in, alias, password, keyStore.getName());
	}

	/**
	 * 获得{@link Certificate}
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static Certificate getCertificate(InputStream in, String alias, char[] password, String keyStoreType)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = getKeyStore(in, password, keyStoreType);
		return getCertificate(ks, alias);
	}

	/**
	 * 获得{@link Certificate}
	 * 
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws KeyStoreException 
	 */
	public static Certificate getCertificate(KeyStore keyStore, String alias) throws KeyStoreException {
		Certificate certificate = keyStore.getCertificate(alias);
		return certificate;
	}

	/**
	 * 获得证书链
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static Certificate[] getCertificateChain(InputStream in, String alias, char[] password,
			JKeyStoreType keyStore)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		return getCertificateChain(in, alias, password, keyStore.getName());
	}

	/**
	 * 获得证书链
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static Certificate[] getCertificateChain(InputStream in, String alias, char[] password, String keyStoreType)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = getKeyStore(in, password, keyStoreType);
		return getCertificateChain(ks, alias);
	}

	/**
	 * 获得证书链
	 * 
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws KeyStoreException 
	 */
	public static Certificate[] getCertificateChain(KeyStore keyStore, String alias) throws KeyStoreException {
		Certificate[] certificateChain = keyStore.getCertificateChain(alias);
		return certificateChain;
	}

	/**
	 * 获得公钥
	 * 
	 * @param certificate
	 * @return
	 */
	public static PublicKey getPublicKey(Certificate certificate) {
		PublicKey key = certificate.getPublicKey();
		return key;
	}

	/**
	 * 获得公钥{@link PublicKey}
	 * 
	 * @param in
	 * @return
	 * @throws CertificateException 
	 */
	public static PublicKey getPublicKey(InputStream in) throws CertificateException {
		Certificate certificate = getCertificate(in);
		return getPublicKey(certificate);
	}

	/**
	 * 获得公钥{@link PublicKey}
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static PublicKey getPublicKey(InputStream in, String alias, char[] password, JKeyStoreType keyStore)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		return getPublicKey(in, alias, password, keyStore.getName());
	}

	/**
	 * 获得公钥{@link PublicKey}
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static PublicKey getPublicKey(InputStream in, String alias, char[] password, String keyStoreType)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		Certificate certificate = getCertificate(in, alias, password, keyStoreType);
		return getPublicKey(certificate);
	}

	/**
	 * 获得公钥{@link PublicKey}
	 * 
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws KeyStoreException 
	 */
	public static PublicKey getPublicKey(KeyStore keyStore, String alias) throws KeyStoreException {
		Certificate certificate = getCertificate(keyStore, alias);
		return getPublicKey(certificate);
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param date
	 * @param certificate
	 * @return
	 * @throws CertificateNotYetValidException 
	 * @throws CertificateExpiredException 
	 */
	public static boolean verifyCertificate(Date date, Certificate certificate)
			throws CertificateExpiredException, CertificateNotYetValidException {
		X509Certificate x509Certificate = (X509Certificate) certificate;
		x509Certificate.checkValidity(date);
		return true;
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param certificate
	 * @return
	 * @throws CertificateNotYetValidException 
	 * @throws CertificateExpiredException 
	 */
	public static boolean verifyCertificate(Certificate certificate)
			throws CertificateExpiredException, CertificateNotYetValidException {
		return verifyCertificate(new Date(), certificate);
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param in
	 * @return
	 * @throws CertificateException 
	 */
	public static boolean verifyCertificate(InputStream in) throws CertificateException {
		Certificate certificate = getCertificate(in);
		return verifyCertificate(certificate);
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param date
	 * @param in
	 * @return
	 * @throws CertificateException 
	 */
	public static boolean verifyCertificate(Date date, InputStream in) throws CertificateException {
		Certificate certificate = getCertificate(in);
		return verifyCertificate(date, certificate);
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static boolean verifyCertificate(InputStream in, String alias, char[] password, JKeyStoreType keyStore)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		return verifyCertificate(in, alias, password, keyStore.getName());
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static boolean verifyCertificate(InputStream in, String alias, char[] password, String keyStoreType)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		Certificate certificate = getCertificate(in, alias, password, keyStoreType);
		return verifyCertificate(certificate);
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param date
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static boolean verifyCertificate(Date date, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		return verifyCertificate(date, in, alias, password, keyStore.getName());
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param date
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static boolean verifyCertificate(Date date, InputStream in, String alias, char[] password,
			String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		Certificate certificate = getCertificate(in, alias, password, keyStoreType);
		return verifyCertificate(date, certificate);
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws KeyStoreException 
	 * @throws CertificateNotYetValidException 
	 * @throws CertificateExpiredException 
	 */
	public static boolean verifyCertificate(KeyStore keyStore, String alias)
			throws KeyStoreException, CertificateExpiredException, CertificateNotYetValidException {
		Certificate certificate = getCertificate(keyStore, alias);
		return verifyCertificate(certificate);
	}

	/**
	 * 验证{@link Certificate}是否过期或无效
	 * 
	 * @param date
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws KeyStoreException 
	 * @throws CertificateNotYetValidException 
	 * @throws CertificateExpiredException 
	 */
	public static boolean verifyCertificate(Date date, KeyStore keyStore, String alias)
			throws KeyStoreException, CertificateExpiredException, CertificateNotYetValidException {
		Certificate certificate = getCertificate(keyStore, alias);
		return verifyCertificate(date, certificate);
	}

	/**
	 * 签名
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] sign(byte[] data, InputStream in, String alias, char[] password, JKeyStoreType keyStore)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, KeyStoreException,
			CertificateException, IOException, UnrecoverableKeyException {
		return sign(data, in, alias, password, keyStore.getName());
	}

	/**
	 * 签名
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] sign(byte[] data, InputStream in, String alias, char[] password, String keyStoreType)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, KeyStoreException,
			CertificateException, IOException, UnrecoverableKeyException {
		// 获得证书
		Certificate certificate = getCertificate(in, alias, password, keyStoreType);
		// 取得私钥
		PrivateKey privateKey = getPrivateKey(in, alias, password, keyStoreType);
		return sign(data, certificate, privateKey);
	}

	/**
	 * 签名
	 * 
	 * @param data
	 * @param keyStore
	 * @param alias
	 * @param password
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] sign(byte[] data, KeyStore keyStore, String alias, char[] password) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, UnrecoverableKeyException, KeyStoreException {
		// 获得证书
		Certificate certificate = getCertificate(keyStore, alias);
		// 取得私钥
		PrivateKey privateKey = getPrivateKey(keyStore, alias, password);
		return sign(data, certificate, privateKey);
	}

	/**
	 * 签名
	 * 
	 * @param data
	 * @param certificate
	 * @param privateKey
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] sign(byte[] data, Certificate certificate, PrivateKey privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate) certificate;
		return sign(data, privateKey, x509Certificate.getSigAlgName());
	}

	/**
	 * 签名
	 * 
	 * @param data
	 * @param privateKey
	 * @param signatureAlgorithm
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] sign(byte[] data, PrivateKey privateKey, String signatureAlgorithm)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		return CommonUtils.sign(data, privateKey, signatureAlgorithm);
	}

	/**
	 * 验签
	 * 
	 * @param data
	 * @param sign
	 * @param in
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws CertificateException 
	 */
	public static boolean verify(byte[] data, byte[] sign, InputStream in)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, CertificateException {
		// 获得证书
		Certificate certificate = getCertificate(in);

		return verify(data, sign, certificate);
	}

	/**
	 * 验签
	 * 
	 * @param data
	 * @param sign
	 * @param certificate
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static boolean verify(byte[] data, byte[] sign, Certificate certificate)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate) certificate;
		// 获得公钥
		PublicKey publicKey = x509Certificate.getPublicKey();
		return verify(data, sign, publicKey, x509Certificate.getSigAlgName());
	}

	/**
	 * 验签
	 * 
	 * @param data
	 * @param sign
	 * @param publicKey
	 * @param signatureAlgorithm
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static boolean verify(byte[] data, byte[] sign, PublicKey publicKey, String signatureAlgorithm)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		return CommonUtils.verify(data, sign, publicKey, signatureAlgorithm);
	}

	/**
	 * 验签
	 * 
	 * @param data
	 * @param sign
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 */
	public static boolean verify(byte[] data, byte[] sign, KeyStore keyStore, String alias)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, KeyStoreException {
		Certificate certificate = getCertificate(keyStore, alias);
		return verify(data, sign, certificate);
	}

	/**
	 * 验签，遍历密钥库中的所有公钥
	 * 
	 * @param data
	 * @param sign
	 * @param keyStore
	 * @return
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 */
	public static boolean verify(byte[] data, byte[] sign, KeyStore keyStore)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, KeyStoreException {
		Enumeration<String> aliasEnum = keyStore.aliases();
		while (aliasEnum.hasMoreElements()) {
			if (verify(data, sign, keyStore.getCertificate(aliasEnum.nextElement())))
				return true;
		}
		return false;
	}

	/**
	 * 私钥加密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] encryptByPrivate(byte[] data, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		return encryptByPrivate(data, in, alias, password, keyStore.getName());
	}

	/**
	 * 私钥加密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] encryptByPrivate(byte[] data, InputStream in, String alias, char[] password,
			String keyStoreType)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		PrivateKey privateKey = getPrivateKey(in, alias, password, keyStoreType);
		return encrypt(data, privateKey);
	}

	/**
	 * 私钥加密
	 * 
	 * @param data
	 * @param keyStore
	 * @param alias
	 * @param password
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] encryptByPrivate(byte[] data, KeyStore keyStore, String alias, char[] password)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException {
		PrivateKey privateKey = getPrivateKey(keyStore, alias, password);
		return encrypt(data, privateKey);
	}

	/**
	 * 私钥加密
	 * 
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] encrypt(byte[] data, PrivateKey privateKey) throws IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(privateKey, Cipher.ENCRYPT_MODE);
		return CommonUtils.doFinal(data, cipher);
	}

	public static OutputStream wrapByPrivate(OutputStream out, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		return wrapByPrivate(out, in, alias, password, keyStore.getName());
	}

	public static OutputStream wrapByPrivate(OutputStream out, InputStream in, String alias, char[] password,
			String keyStoreType) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		PrivateKey privateKey = getPrivateKey(in, alias, password, keyStoreType);
		return wrap(out, privateKey);
	}

	public static OutputStream wrapByPrivate(OutputStream out, KeyStore keyStore, String alias, char[] password)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException,
			KeyStoreException {
		PrivateKey privateKey = getPrivateKey(keyStore, alias, password);
		return wrap(out, privateKey);
	}

	public static OutputStream wrap(OutputStream out, PrivateKey privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(privateKey, Cipher.ENCRYPT_MODE);
		return new CipherOutputStream(out, cipher);
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param certificate
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] encrypt(byte[] data, Certificate certificate) throws IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		PublicKey publicKey = certificate.getPublicKey();
		return encrypt(data, publicKey);
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param in
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws CertificateException 
	 */
	public static byte[] encryptByPublic(byte[] data, InputStream in)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, CertificateException {
		PublicKey publicKey = getPublicKey(in);
		return encrypt(data, publicKey);
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] encryptByPublic(byte[] data, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore) throws IllegalBlockSizeException, BadPaddingException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchPaddingException {
		return encryptByPublic(data, in, alias, password, keyStore.getName());
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] encryptByPublic(byte[] data, InputStream in, String alias, char[] password,
			String keyStoreType) throws IllegalBlockSizeException, BadPaddingException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchPaddingException {
		PublicKey publicKey = getPublicKey(in, alias, password, keyStoreType);
		return encrypt(data, publicKey);
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 */
	public static byte[] encryptByPublic(byte[] data, KeyStore keyStore, String alias)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, KeyStoreException {
		PublicKey publicKey = getPublicKey(keyStore, alias);
		return encrypt(data, publicKey);
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] encrypt(byte[] data, PublicKey publicKey) throws IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(publicKey, Cipher.ENCRYPT_MODE);
		return CommonUtils.doFinal(data, cipher);
	}

	public static OutputStream wrap(OutputStream out, Certificate certificate)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		PublicKey publicKey = certificate.getPublicKey();
		return wrap(out, publicKey);
	}

	public static OutputStream wrapByPublic(OutputStream out, InputStream in)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, CertificateException {
		PublicKey publicKey = getPublicKey(in);
		return wrap(out, publicKey);
	}

	public static OutputStream wrapByPublic(OutputStream out, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, InvalidKeyException, NoSuchPaddingException {
		return wrapByPublic(out, in, alias, password, keyStore.getName());
	}

	public static OutputStream wrapByPublic(OutputStream out, InputStream in, String alias, char[] password,
			String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidKeyException, NoSuchPaddingException {
		PublicKey publicKey = getPublicKey(in, alias, password, keyStoreType);
		return wrap(out, publicKey);
	}

	public static OutputStream wrapByPublic(OutputStream out, KeyStore keyStore, String alias)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException {
		PublicKey publicKey = getPublicKey(keyStore, alias);
		return wrap(out, publicKey);
	}

	public static OutputStream wrap(OutputStream out, PublicKey publicKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(publicKey, Cipher.ENCRYPT_MODE);
		return new CipherOutputStream(out, cipher);
	}

	/**
	 * 私钥解密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] decryptByPrivate(byte[] data, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		return decryptByPrivate(data, in, alias, password, keyStore.getName());
	}

	/**
	 * 私钥解密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] decryptByPrivate(byte[] data, InputStream in, String alias, char[] password,
			String keyStoreType)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		PrivateKey privateKey = getPrivateKey(in, alias, password, keyStoreType);
		return decrypt(data, privateKey);
	}

	/**
	 * 私钥解密
	 * 
	 * @param data
	 * @param keyStore
	 * @param alias
	 * @param password
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static byte[] decryptByPrivate(byte[] data, KeyStore keyStore, String alias, char[] password)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException {
		// 取得私钥
		PrivateKey privateKey = getPrivateKey(keyStore, alias, password);
		return decrypt(data, privateKey);
	}

	/**
	 * 私钥解密
	 * 
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(privateKey, Cipher.DECRYPT_MODE);
		return CommonUtils.doFinal(data, cipher);
	}

	public static InputStream wrapByPrivate(InputStream sIn, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		return wrapByPrivate(sIn, in, alias, password, keyStore.getName());
	}

	public static InputStream wrapByPrivate(InputStream sIn, InputStream in, String alias, char[] password,
			String keyStoreType) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
		PrivateKey privateKey = getPrivateKey(in, alias, password, keyStoreType);
		return wrap(sIn, privateKey);
	}

	public static InputStream wrapByPrivate(InputStream sIn, KeyStore keyStore, String alias, char[] password)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException,
			KeyStoreException {
		PrivateKey privateKey = getPrivateKey(keyStore, alias, password);
		return wrap(sIn, privateKey);
	}

	public static InputStream wrap(InputStream sIn, PrivateKey privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(privateKey, Cipher.ENCRYPT_MODE);
		return new CipherInputStream(sIn, cipher);
	}

	/**
	 * 公钥解密
	 * 
	 * @param data
	 * @param certificate
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] decrypt(byte[] data, Certificate certificate) throws IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		PublicKey publicKey = certificate.getPublicKey();
		return decrypt(data, publicKey);
	}

	/**
	 * 公钥解密
	 * 
	 * @param data
	 * @param in
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws CertificateException 
	 */
	public static byte[] decryptByPublic(byte[] data, InputStream in)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, CertificateException {
		PublicKey publicKey = getPublicKey(in);
		return decrypt(data, publicKey);
	}

	/**
	 * 公钥解密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] decryptByPublic(byte[] data, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore) throws IllegalBlockSizeException, BadPaddingException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchPaddingException {
		return decryptByPublic(data, in, alias, password, keyStore.getName());
	}

	/**
	 * 公钥解密
	 * 
	 * @param data
	 * @param in
	 * @param alias
	 * @param password
	 * @param keyStore
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] decryptByPublic(byte[] data, InputStream in, String alias, char[] password,
			String keyStoreType) throws IllegalBlockSizeException, BadPaddingException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchPaddingException {
		PublicKey publicKey = getPublicKey(in, alias, password, keyStoreType);
		return decrypt(data, publicKey);
	}

	/**
	 * 公钥解密
	 * 
	 * @param data
	 * @param keyStore
	 * @param alias
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 */
	public static byte[] decryptByPublic(byte[] data, KeyStore keyStore, String alias)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, KeyStoreException {
		PublicKey publicKey = getPublicKey(keyStore, alias);
		return decrypt(data, publicKey);
	}

	/**
	 * 公钥解密
	 * 
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] decrypt(byte[] data, PublicKey publicKey) throws IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(publicKey, Cipher.DECRYPT_MODE);
		return CommonUtils.doFinal(data, cipher);
	}

	public static InputStream wrap(InputStream sIn, Certificate certificate)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		PublicKey publicKey = certificate.getPublicKey();
		return wrap(sIn, publicKey);
	}

	public static InputStream wrapByPublic(InputStream sIn, InputStream in)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, CertificateException {
		PublicKey publicKey = getPublicKey(in);
		return wrap(sIn, publicKey);
	}

	public static InputStream wrapByPublic(InputStream sIn, InputStream in, String alias, char[] password,
			JKeyStoreType keyStore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, InvalidKeyException, NoSuchPaddingException {
		return wrapByPublic(sIn, in, alias, password, keyStore.getName());
	}

	public static InputStream wrapByPublic(InputStream sIn, InputStream in, String alias, char[] password,
			String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidKeyException, NoSuchPaddingException {
		PublicKey publicKey = getPublicKey(in, alias, password, keyStoreType);
		return wrap(sIn, publicKey);
	}

	public static InputStream wrapByPublic(InputStream sIn, KeyStore keyStore, String alias)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException {
		PublicKey publicKey = getPublicKey(keyStore, alias);
		return wrap(sIn, publicKey);
	}

	public static InputStream wrap(InputStream sIn, PublicKey publicKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = getCipher(publicKey, Cipher.DECRYPT_MODE);
		return new CipherInputStream(sIn, cipher);
	}

	public static Cipher getCipher(Key key, int opmode)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		CommonUtils.checkOpMode(opmode);
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(opmode, key);
		return cipher;
	}

	/**
	 * 导出公钥证书
	 * 
	 * @param out
	 * @param certificate
	 * @param rfc
	 * @throws CertificateEncodingException 
	 * @throws IOException 
	 */
	public static void export(OutputStream out, Certificate certificate, boolean rfc)
			throws CertificateEncodingException, IOException {
		byte[] encoded = certificate.getEncoded();
		if (rfc) {
			out.write("-----BEGIN CERTIFICATE-----\r\n".getBytes());
			out.write(Base64.getEncoder().encode(encoded));
			out.write("\r\n-----END CERTIFICATE-----\r\n".getBytes());
		} else
			out.write(encoded);
		out.flush();
	}

	/**
	 * 将密钥库转换为指定类型的密钥库
	 * 
	 * @param srcKeyStore
	 * @param target
	 * @param password
	 * @param alias
	 *           导出指定别名的证书
	 * @return
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static KeyStore convert(KeyStore srcKeyStore, JKeyStoreType target, char[] password, String... alias)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException {
		return convert(srcKeyStore, target.getName(), password, alias);
	}

	/**
	 * 将密钥库转换为指定类型的密钥库
	 * 
	 * @param srcKeyStore
	 * @param target
	 * @param password
	 * @param alias 导出指定别名的证书
	 * @return
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableKeyException 
	 */
	public static KeyStore convert(KeyStore srcKeyStore, String target, char[] password, String... alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException {
		KeyStore outputKeyStore = KeyStore.getInstance(target);
		outputKeyStore.load(null, password);
		if (alias.length == 0) {
			Enumeration<String> enums = srcKeyStore.aliases();
			while (enums.hasMoreElements()) {
				String keyAlias = enums.nextElement();
				copyKeyEntry(srcKeyStore, outputKeyStore, keyAlias, password);
			}
		} else {
			for (String keyAlias : alias) {
				copyKeyEntry(srcKeyStore, outputKeyStore, keyAlias, password);
			}
		}
		return outputKeyStore;
	}

	/**
	 * 复制
	 * 
	 * @param src
	 * @param target
	 * @param alias
	 * @param password
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 */
	public static void copyKeyEntry(KeyStore src, KeyStore target, String alias, char[] password)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		if (src.isKeyEntry(alias)) {
			Key key = src.getKey(alias, password);
			Certificate[] certChain = src.getCertificateChain(alias);
			target.setKeyEntry(alias, key, password, certChain);
		}
	}

}
