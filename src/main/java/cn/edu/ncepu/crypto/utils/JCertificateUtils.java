/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 25, 2020 3:02:06 PM
 * @ClassName CertificateUtils
 * @Description: TODO(utilize certificate to realize the function of 
 * digital signature, identity authentication, data encryption and decryption)
 */
public class JCertificateUtils {

	/**
	 * @Description: TODO(generate key store file)
	 * storepass : keystore password
	 * keyalg：encryption algorithm e.g., RSA；
	 * keysize size of the key
	 * sigalg：signature algorithm e.g., SHA1withRSA；
	 * validity：validity days of the certificate；
	 * dname: Unique distinguished name(CN: common name, if the certificateis used https,it should be the same as domain name)
	 * @throws
	 */
	public static void genKeyStore() {
		String shell = "keytool -genkey -storepass 1962111mm -keyalg RSA -keysize 1024 -sigalg SHA1withRSA -validity 3650 -alias mykeystore "
				+ "-keystore my.keystore";
		CommonUtils.callCMD(shell, null);
	}

	/**
	 * @Description: TODO(export certificate file from key store)
	 * storepass : keystore password
	 * alias：the name of certificate in programme；
	 * keystore: name of the keystore
	 * rfc output in the form of RFC
	 * @throws
	 */
	public static void exportCer() {
		String shell = "keytool -export -storepass 1962111mm -keystore my.keystore -alias mycert -file my.cer -rfc";
		CommonUtils.callCMD(shell, null);
	}

	public static void loadKeyStore() {

	}

//	public static KeyStore loadKeyStore(String keyStoreFilepath, String password) {
//		try (InputStream input = Main.class.getResourceAsStream(keyStoreFile)) {
//			if (input == null) {
//				throw new RuntimeException("file not found in classpath: " + keyStoreFile);
//			}
//			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//			ks.load(input, password.toCharArray());
//			return ks;
//		} catch (Exception e) {
//			throw new RuntimeException(e);
//		}
//	}

	public static byte[] encrypt(X509Certificate certificate, byte[] message) {
		try {
			Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
			return cipher.doFinal(message);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] decrypt(PrivateKey privateKey, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] sign(PrivateKey privateKey, X509Certificate certificate, byte[] message) {
		try {
			Signature signature = Signature.getInstance(certificate.getSigAlgName());
			signature.initSign(privateKey);
			signature.update(message);
			return signature.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}

	static boolean verify(X509Certificate certificate, byte[] message, byte[] sig) {
		try {
			Signature signature = Signature.getInstance(certificate.getSigAlgName());
			signature.initVerify(certificate);
			signature.update(message);
			return signature.verify(sig);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return false;
	}
}
