/**
 * 
 */
package com.example.utils;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.CertificateUtils;
import cn.edu.ncepu.crypto.utils.CertificateUtils.JKeyStoreType;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.EccUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 21, 2020 12:08:45 AM
 * @ClassName CommonUtilsTest
 * @Description:  (test methods of CommonUtils)
 */
public class CommonUtilsTest {
	private static final Logger logger = LoggerFactory.getLogger(CommonUtilsTest.class);
	private static final String USER_DIR = SysProperty.USER_DIR;
	private static final String EC_STRING = "EC";
	private static final int TIMES = 100_000;

	@Ignore
	@Test
	public void testCallCMD() {
		String shell = "pwd";
		try {
			CommonUtils.callCMD(shell, USER_DIR + "/elements");
			shell = "ls -al";
			CommonUtils.callCMD(shell, USER_DIR + "/elements");
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testCallScript() {
		String args = "1 2 3";
		try {
			CommonUtils.callScript("testCallScript.sh", args, USER_DIR + "/scripts");
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testHash() {
		String content = "HelloWorld";

		// utilize jdk
		String algorithm = "SHA256";
		logger.info("Hash Algorithm: " + algorithm);
		String hexHash = CommonUtils.hash(content, algorithm);
		logger.info("hex hash digest: " + hexHash);
		logger.info("hex hash digest length: " + hexHash.length());

		// utilize third party library.
		String hash = DigestUtils.sha256Hex(content);
		assertEquals(hexHash, hash);
	}

	public static long sha256() {
		String message = generateStringToHash();
		StopWatch watch = new StopWatch();
		int BATCH_SIZE = 10;
		long count = 0;
		for (int i = 0; i < BATCH_SIZE; i++) {
			watch.start();
			for (int j = 0; j < TIMES; j++) {
				DigestUtils.sha256Hex(message);
			}
			watch.stop();
			count += watch.getTime();
			watch.reset();
		}
		count = count / BATCH_SIZE;
		return count;
	}

	public static String generateStringToHash() {
		String UUID_STRING = UUID.randomUUID().toString();
		return UUID_STRING + System.currentTimeMillis();
	}

	@Ignore
	@Test
	public void testHashTimeCost() {
		logger.info(generateStringToHash());
//		System.out.println("MD5: " + md5());
//		System.out.println("SHA-1: " + sha1());
		logger.info("SHA-256: " + sha256());
//		System.out.println("SHA-512: " + sha512());
	}

	@Ignore
	@Test
	public void testSignAndVerify() {
		try {
			String message = "Hello, use X.509 cert!";
			String algorithm = "SHA256";
			byte[] hexHash = CommonUtils.hash(message.getBytes(StandardCharsets.UTF_8), algorithm);
			// 从keystore file读取KeyStore:
			FileInputStream input = new FileInputStream(new File(USER_DIR + "/elements/my.keystore"));
			KeyStore ks = CertificateUtils.getKeyStore(input, "123456".toCharArray(), JKeyStoreType.JKS);
			// 从keyStore读取私钥:
			String alias = "mykeystore1";
			PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "123456".toCharArray());
			logger.info("privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());
			// 从keyStore读取证书:
			X509Certificate certificate = (X509Certificate) ks.getCertificate("mykeystore1");
			logger.info("certificate signature algorithm: " + certificate.getSigAlgName());
			logger.info("certificate encryption algorithm: " + certificate.getPublicKey().getAlgorithm());
			// 从证书读取publicKey
			PublicKey publicKey = certificate.getPublicKey();
			logger.info("Test SHA256withRSA signature.");
			// 签名:
			byte[] sign = CommonUtils.sign(hexHash, privateKey, certificate.getSigAlgName());
			String singHex = Hex.encodeHexString(sign);
			logger.info("Hex signature: " + singHex);
			logger.info(String.format("signature: %x", new BigInteger(1, sign)));
			logger.info("Signature length = " + singHex.length());
			// 验证签名:
			if (false == CommonUtils.verify(hexHash, sign, publicKey, certificate.getSigAlgName())) {
				logger.info("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}
			logger.info("SHA256withRSA signer functionality test pass.");
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}

	}

	@Ignore
	@Test
	public void testEncodeHex() {
		String content = "abc123!@#阿萨德'}|";
		logger.info("initial content " + content);
		try {
			// encode
			String hexdata = CommonUtils.encodeHexString(content.getBytes(StandardCharsets.UTF_8));
			// decode
			String decoded = new String(Hex.decodeHex(hexdata));
			logger.info("encoded Hex string: " + hexdata);
			logger.info("decoded content " + decoded);
			assertEquals(content, decoded);
		} catch (DecoderException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testDecodeHex() {
		String content = "abc123!@#阿萨德'}|";
		logger.info("initial content " + content);
		try {
			final String hexdata = Hex.encodeHexString(content.getBytes(StandardCharsets.UTF_8));
			logger.info("encoded Hex string: " + hexdata);
			String decoded = new String(CommonUtils.decodeHex(hexdata));
			logger.info("decoded content " + decoded);
			assertEquals(content, decoded);
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testURLEncodeDecode() {
		// encode
		String encoded;
		try {
			encoded = CommonUtils.encodeURLString("中文!");
			logger.info("URL encoded = " + encoded);
			// decode
			String decoded = CommonUtils.decodeURL(encoded);
			logger.info("URL decoded = " + decoded);
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testSaveKeyAsPEM() {
		KeyPair keyPair;
		try {
//			keyPair = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			keyPair = EccUtils.getKeyPair(256);
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
			CommonUtils.saveKeyAsPEM(publicKey, USER_DIR + "/elements/ECPublicKey.pem");
			CommonUtils.saveKeyAsPEM(privateKey, USER_DIR + "/elements/ECPrivateKey.pem");
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		}

	}

	@Ignore
	@Test
	public void testSaveECKeyAsDER() {
		KeyPair keyPair;
		try {
//			keyPair = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			keyPair = EccUtils.getKeyPair(256);
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
			CommonUtils.saveKeyAsDER(publicKey, USER_DIR + "/elements/ECPublicKey.der");
			CommonUtils.saveKeyAsDER(privateKey, USER_DIR + "/elements/ECPrivateKey.der");
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testLoadECKeyFromPEM() {
		try {
			ECPublicKey publicKey = (ECPublicKey) CommonUtils.loadKeyFromPEM(true, EC_STRING,
					USER_DIR + "/elements/ECPublicKey.pem");
			ECPrivateKey privateKey = (ECPrivateKey) CommonUtils.loadKeyFromPEM(false, EC_STRING,
					USER_DIR + "/elements/ECPrivateKey.pem");
			logger.info("Base64 publicKey length = " + EccUtils.publicKey2String(publicKey).length());
			logger.info("Base64 privateKey length = " + EccUtils.privateKey2String(privateKey).length());

			logger.info("Hex string publicKey length = " + Hex.encodeHexString(publicKey.getEncoded()).length());
			logger.info("Hex string privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());
			logger.info("========================================");
			// signature
			byte[] signed = ECDSASigner.sign(privateKey, "message".getBytes(StandardCharsets.UTF_8));
			String signature = Hex.encodeHexString(signed);
			logger.info("Hex Signature String = " + signature);
			logger.info("Hex Signature length = " + signature.length());

			// verify
			if (false == ECDSASigner.verify(publicKey, "message".getBytes(StandardCharsets.UTF_8), signed)) {
				logger.info("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}
			logger.info("ECDSA signer functionality test pass.");
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (DecoderException e) {
			e.printStackTrace();
		} catch (Exception e) {
			//   Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Ignore
	@Test
	public void testLoadECKeyFromDER() {
		try {
			ECPublicKey publicKey = (ECPublicKey) CommonUtils.loadKeyFromDER(true, EC_STRING,
					USER_DIR + "/elements/ECPublicKey.der");
			ECPrivateKey privateKey = (ECPrivateKey) CommonUtils.loadKeyFromDER(false, EC_STRING,
					USER_DIR + "/elements/ECPrivateKey.der");

			logger.info("Base64 publicKey length = " + EccUtils.publicKey2String(publicKey).length());
			logger.info("Base64 privateKey length = " + EccUtils.privateKey2String(privateKey).length());

			logger.info("Hex string publicKey length = " + Hex.encodeHexString(publicKey.getEncoded()).length());
			logger.info("Hex string privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());
			logger.info("========================================");
			// signature
			byte[] signed = ECDSASigner.sign(privateKey, "message".getBytes(StandardCharsets.UTF_8));
			String signature = Hex.encodeHexString(signed);
			logger.info("Hex Signature String = " + signature);
			logger.info("Hex Signature length = " + signature.length());

			// verify
			if (false == ECDSASigner.verify(publicKey, "message".getBytes(StandardCharsets.UTF_8), signed)) {
				logger.info("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}
			logger.info("ECDSA signer functionality test pass.");
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}

	}

	@Ignore
	@Test
	public void testXOR() {
		byte[] num1bytes = new BigInteger("21").toByteArray();
		byte[] num2bytes = new BigInteger("65").toByteArray();
		byte[] result = CommonUtils.xor(num1bytes, num2bytes);
		logger.info("" + new BigInteger(result));
		logger.info("" + new BigInteger("21").xor(new BigInteger("65")));
	}

}
