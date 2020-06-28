/**
 * 
 */
package com.example.utils;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 21, 2020 12:08:45 AM
 * @ClassName CommonUtilsTest
 * @Description: TODO(test methods of CommonUtils)
 */
public class CommonUtilsTest {
	private static Logger logger = LoggerFactory.getLogger(CommonUtilsTest.class);
	private static String USER_DIR = SysProperty.USER_DIR;
	private static final String EC_STRING = "EC";
	private static final String CURVE_NAME = "secp256k1";

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
	public void testGenHash() {
		try {
			String content = "HelloWorld";

			// utilize jdk
			String algorithm = "SHA256";
			logger.info("Hash Algorithm: " + algorithm);
			String hexHash = CommonUtils.genHash(content, algorithm);
			logger.info("hex hash digest: " + hexHash);
			logger.info("hex hash digest length: " + hexHash.length());

			// utilize third party library.
			String hash = DigestUtils.sha256Hex(content);
			assertEquals(hexHash, hash);
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
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
			String hexdata = CommonUtils.encodeHexString(content.getBytes("UTF-8"));
			// decode
			String decoded = new String(Hex.decodeHex(hexdata));
			logger.info("encoded Hex string: " + hexdata);
			logger.info("decoded content " + decoded);
			assertEquals(content, decoded);
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
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
			final String hexdata = Hex.encodeHexString(content.getBytes("UTF-8"));
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
		try {
			KeyPair keyPair = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			CommonUtils.saveKeyAsPEM(publicKey, USER_DIR + "/elements/publicKey.pem");
			CommonUtils.saveKeyAsPEM(privateKey, USER_DIR + "/elements/privateKey.pem");
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testSaveECKeyAsDER() {
		KeyPair keyPair;
		try {
			keyPair = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			CommonUtils.saveKeyAsDER(publicKey, USER_DIR + "/elements/publicKey.der");
			CommonUtils.saveKeyAsDER(privateKey, USER_DIR + "/elements/privateKey.der");
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testLoadECKeyFromPEM() {
		try {
			PublicKey publicKey = null;
			PrivateKey privateKey = null;
			publicKey = (PublicKey) CommonUtils.loadKeyFromPEM(true, EC_STRING, USER_DIR + "/elements/publicKey.pem");
			privateKey = (PrivateKey) CommonUtils.loadKeyFromPEM(false, EC_STRING,
					USER_DIR + "/elements/privateKey.pem");
			logger.info(
					"Base64 publicKey length = " + Base64.getEncoder().encodeToString(publicKey.getEncoded()).length());
			logger.info("Base64 privateKey length = "
					+ Base64.getEncoder().encodeToString(privateKey.getEncoded()).length());

			logger.info("Hex string publicKey length = " + Hex.encodeHexString(publicKey.getEncoded()).length());
			System.out
					.println("Hex string privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());
			logger.info("========================================");
			// signature
			byte[] signed = ECDSASigner.signECDSA(privateKey, "message".getBytes("UTF-8"));
			String signature = Hex.encodeHexString(signed);
			logger.info("Hex Signature String = " + signature);
			logger.info("Hex Signature length = " + signature.length());

			// verify
			if (false == ECDSASigner.verifyECDSA(publicKey, "message".getBytes("UTF-8"), signed)) {
				logger.info("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}
			logger.info("ECDSA signer functionality test pass.");
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}

	}

	@Ignore
	@Test
	public void testLoadECKeyFromDER() {
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		try {
			publicKey = (PublicKey) CommonUtils.loadKeyFromDER(true, EC_STRING, USER_DIR + "/elements/publicKey.der");
			privateKey = (PrivateKey) CommonUtils.loadKeyFromDER(false, EC_STRING,
					USER_DIR + "/elements/privateKey.der");

			logger.info(
					"Base64 publicKey length = " + Base64.getEncoder().encodeToString(publicKey.getEncoded()).length());
			logger.info("Base64 privateKey length = "
					+ Base64.getEncoder().encodeToString(privateKey.getEncoded()).length());

			logger.info("Hex string publicKey length = " + Hex.encodeHexString(publicKey.getEncoded()).length());
			System.out
					.println("Hex string privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());
			logger.info("========================================");
			// signature
			byte[] signed = ECDSASigner.signECDSA(privateKey, "message".getBytes("UTF-8"));
			String signature = Hex.encodeHexString(signed);
			logger.info("Hex Signature String = " + signature);
			logger.info("Hex Signature length = " + signature.length());

			// verify
			if (false == ECDSASigner.verifyECDSA(publicKey, "message".getBytes("UTF-8"), signed)) {
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
	public void testPrintECKeywithOpenssl() {
		logger.info("==================DER publicKey==================");
		try {
			CommonUtils.printECKeywithOpenssl(true, true, USER_DIR + "/elements/publicKey.der");
			logger.info("\n==================DER privateKey==================");
			CommonUtils.printECKeywithOpenssl(false, true, USER_DIR + "/elements/privateKey.der");
			logger.info("\n");
			logger.info("==================PEM publicKey==================");
			CommonUtils.printECKeywithOpenssl(true, false, USER_DIR + "/elements/publicKey.pem");
			logger.info("\n==================PEM privateKey==================");
			CommonUtils.printECKeywithOpenssl(false, false, USER_DIR + "/elements/privateKey.pem");
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}

}
