/**
 * 
 */
package com.example.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.utils.CertificateUtils;
import cn.edu.ncepu.crypto.utils.CertificateUtils.JKeyStoreType;
import cn.edu.ncepu.crypto.utils.SysProperty;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 26, 2020 2:49:49 PM
 * @ClassName CertificateUtilsTest
 * @Description: TODO(test the function of CertificateUtils)
 */
public class CertificateUtilsTest {
	private static Logger logger = LoggerFactory.getLogger(CertificateUtilsTest.class);
	private static String USER_DIR = SysProperty.USER_DIR;

	@Ignore
	@Test
	public void testGenKeyStore_exportCer() {
		try {
			String[] aliasArray = new String[] { "mykeystore1", "mykeystore2", "mykeystore3" };
			for (int i = 0; i < aliasArray.length; i++) {
				CertificateUtils.exportKeyStore(aliasArray[i]);
			}
			Thread.sleep(500);
			CertificateUtils.exportCer("mykeystore1");
		} catch (InterruptedException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testLoadCer() {
		byte[] message;
		try {
			message = "Hello, use X.509 cert!".getBytes("UTF-8");
			logger.info(new String(message, "UTF-8"));
			// 从keystore file读取KeyStore:
			FileInputStream input = new FileInputStream(new File(USER_DIR + "/elements/my.keystore"));
			KeyStore ks = CertificateUtils.getKeyStore(input, "123456".toCharArray(), JKeyStoreType.JKS);
			// 从keyStore读取私钥:
			String alias = "mykeystore1";
			PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "123456".toCharArray());
			// 从keyStore读取证书:
			X509Certificate certificate = (X509Certificate) ks.getCertificate("mykeystore1");
			logger.info("certificate signature algorithm: " + certificate.getSigAlgName());
			logger.info("certificate encryption algorithm: " + certificate.getPublicKey().getAlgorithm());
			// 从证书读取公钥加密:
			byte[] encrypted = CertificateUtils.encrypt(message, certificate);
			logger.info(String.format("encrypted: %x", new BigInteger(1, encrypted)));
			logger.info(String.format("encrypted: %s", Hex.toHexString(encrypted)));
			// 私钥解密:
			byte[] decrypted = CertificateUtils.decrypt(encrypted, privateKey);
			logger.info("decrypted: " + new String(decrypted, "UTF-8"));
			// 签名:
			byte[] sign = CertificateUtils.sign(message, certificate, privateKey);
			logger.info(String.format("signature: %x", new BigInteger(1, sign)));
			// 验证签名:
			boolean verified = CertificateUtils.verify(message, sign, certificate);
			logger.info("verify: " + verified);
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (FileNotFoundException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalBlockSizeException e) {
			logger.error(e.getLocalizedMessage());
		} catch (BadPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (SignatureException e) {
			logger.error(e.getLocalizedMessage());
		} catch (CertificateException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (KeyStoreException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (UnrecoverableKeyException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testPrintCertificate() {
		try {
			SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			char[] password = "123456".toCharArray();
			String alias = "mykeystore1";
			String certificatePath = USER_DIR + "/elements/my.cer";
			String keyStorePath = USER_DIR + "/elements/my.keystore"; // "my.pfx";
			byte[] data = "Hello, use X.509 cert!".getBytes("UTF-8");
			logger.info(new String(data, "UTF-8"));

			FileInputStream input = new FileInputStream(keyStorePath);
			// JSK == KeyStore.getDefaultType();
			KeyStore keyStore = CertificateUtils.getKeyStore(input, password, JKeyStoreType.JKS);

			// 从certificate file读取证书:
			input = new FileInputStream(certificatePath);
			X509Certificate certificate = (X509Certificate) CertificateUtils.getCertificate(input);
			logger.info("certificate signature algorithm: " + certificate.getSigAlgName());
			logger.info("certificate encryption algorithm: " + certificate.getPublicKey().getAlgorithm());

			// 从KeyStore读取私钥
			PrivateKey privateKey = CertificateUtils.getPrivateKey(keyStore, alias, password);
			// 从Certificate读取公钥
			PublicKey publicKey = CertificateUtils.getPublicKey(certificate);

			logger.info("是否有效：" + CertificateUtils.verifyCertificate(certificate));
			logger.info("使用者：" + certificate.getSubjectDN().getName());
			logger.info("版本：" + certificate.getVersion());
			logger.info("序列号：" + certificate.getSerialNumber().toString(16));
			logger.info("签名算法：" + certificate.getSigAlgName());
			logger.info("证书类型：" + certificate.getType());
			logger.info("颁发者：" + certificate.getIssuerDN().getName());
			logger.info("有效期：" + format.format(certificate.getNotBefore()) + "到"
					+ format.format(certificate.getNotAfter()));

			byte[] result = CertificateUtils.encrypt(data, privateKey);
			logger.info("私钥加密：" + Base64.getEncoder().encodeToString(result));
			logger.info("公钥解密：" + new String(CertificateUtils.decrypt(result, publicKey), "UTF-8"));

			result = CertificateUtils.encrypt(data, publicKey);
			logger.info("公钥加密：" + Base64.getEncoder().encodeToString(result));
			logger.info("私钥解密：" + new String(CertificateUtils.decrypt(result, privateKey), "UTF-8"));

			byte[] signResult = CertificateUtils.sign(data, keyStore, alias, password);
			logger.info("签名：" + Base64.getEncoder().encodeToString(signResult));
			logger.info("证书验签：" + CertificateUtils.verify(data, signResult, certificate));
			logger.info("密钥库验签：" + CertificateUtils.verify(data, signResult, keyStore));

		} catch (FileNotFoundException e) {
			logger.error(e.getLocalizedMessage());
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalBlockSizeException e) {
			logger.error(e.getLocalizedMessage());
		} catch (BadPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (SignatureException e) {
			logger.error(e.getLocalizedMessage());
		} catch (KeyStoreException e) {
			logger.error(e.getLocalizedMessage());
		} catch (CertificateException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (UnrecoverableKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchPaddingException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testConvertKeystoreType() {
		try {
			char[] password = "123456".toCharArray();
			String keyStorePath = USER_DIR + "/elements/my.keystore";

			FileInputStream input = new FileInputStream(keyStorePath);
			KeyStore keyStore = CertificateUtils.getKeyStore(input, password, JKeyStoreType.JKS);
			KeyStore target = CertificateUtils.convert(keyStore, JKeyStoreType.PKCS12, password);
			int i = 0;
			for (String alias : CertificateUtils.listAlias(target)) {
				logger.info("certificate " + i++ + ": " + alias);
			}
			target.store(new FileOutputStream(USER_DIR + "/elements/my.pfx"), password);
		} catch (KeyStoreException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (CertificateException e) {
			logger.error(e.getLocalizedMessage());
		} catch (FileNotFoundException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (UnrecoverableKeyException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
