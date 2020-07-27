package com.example.signature.ecdsa;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.bouncycastle.crypto.Signer;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.EccUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 18, 2020 3:24:26 PM
 * @ClassName ECDSASignerTest
 * @Description: TODO(elliptic curve based dsa(Digital Signature Algorithm) test.)
 */
public class ECDSASignerTest {
	private static Logger logger = LoggerFactory.getLogger(ECDSASignerTest.class);
	private PairingKeyPairGenerator asymmetricKeySerPairGenerator;
	private static final String EC_STRING = "EC";
	private static final String CURVE_NAME = "secp256k1";
	private Signer signer;
	private static String USER_DIR = SysProperty.USER_DIR;
	private static final int TIMES = 100_000;

	@Ignore
	@Test
	public void testECDSASigner() {
		try {
			// keyGen
//			KeyPair keyPair = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			KeyPair keyPair = EccUtils.getKeyPair(256);

			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

			// 生成一个Base64编码的公钥字符串，可用来传输
			String ecBase64PublicKey = EccUtils.publicKey2String(publicKey);
			String ecBase64PrivateKey = EccUtils.privateKey2String(privateKey);
			logger.info("[publickey]:\t" + ecBase64PublicKey);
			logger.info("[privateKey]:\t" + ecBase64PrivateKey);

			// 从base64编码的字符串恢复密钥
			ECPublicKey publicKey2 = EccUtils.string2PublicKey(ecBase64PublicKey);
			ECPrivateKey privateKey2 = EccUtils.string2PrivateKey(ecBase64PrivateKey);

			logger.info("Test Scott-Vanstone 1992 signature.");
			logger.info("========================================");
			logger.info("Test signer functionality");

			// signature
			byte[] message = "message".getBytes("UTF-8");
			byte[] sign = ECDSASigner.sign(privateKey2, message);
			String singHex = Hex.encodeHexString(sign);
			logger.info("Hex signature: " + singHex);
			logger.info("Signature length = " + singHex.length());

			// verify
			if (false == ECDSASigner.verify(publicKey2, "message".getBytes("UTF-8"), sign)) {
				logger.info("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}

			logger.info("ECDSA signer functionality test pass.");

			logger.info("========================================");
			logger.info("Test signer parameters serialization & de-serialization.");
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (DecoderException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (SignatureException e) {
			logger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testSignTimeCost() {
		String message = "NACCFFFFFFFF";
		String hexString = DigestUtils.sha256Hex(message);
		ECPrivateKey privateKey = null;
		try {
			privateKey = (ECPrivateKey) CommonUtils.loadKeyFromPEM(false, EC_STRING,
					USER_DIR + "/elements/ECPrivateKey.pem");
			byte[] bytes = hexString.getBytes("UTF-8");
			StopWatch watch = new StopWatch();
			watch.start();
			for (int i = 0; i < TIMES; i++) {
				ECDSASigner.sign(privateKey, bytes);
			}
			watch.stop();
			logger.info("ECDSA sign: " + watch.getTime());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (SignatureException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testVerifyTimeCost() {
		String message = "NACCFFFFFFFF";
		String hexString = DigestUtils.sha256Hex(message);
		ECPublicKey publicKey = null;
		ECPrivateKey privateKey = null;
		try {
			publicKey = (ECPublicKey) CommonUtils.loadKeyFromPEM(true, EC_STRING,
					USER_DIR + "/elements/ECPublicKey.pem");
			privateKey = (ECPrivateKey) CommonUtils.loadKeyFromPEM(false, EC_STRING,
					USER_DIR + "/elements/ECPrivateKey.pem");
			byte[] bytes = hexString.getBytes("UTF-8");
			byte[] sign = ECDSASigner.sign(privateKey, bytes);
			StopWatch watch = new StopWatch();
			watch.start();
			for (int i = 0; i < TIMES; i++) {
				ECDSASigner.verify(publicKey, bytes, sign);
			}
			watch.stop();
			logger.info("ECDSA sign: " + watch.getTime());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (SignatureException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		} catch (DecoderException e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		}
	}

}
