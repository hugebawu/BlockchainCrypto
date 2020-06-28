package com.example.signature.ecdsa;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.CommonUtils;

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
	private static final String EC_STRING = "EC";
	private static final String CURVE_NAME = "secp256k1";

	@Ignore
	@Test
	public void testECDSASigner() {

		try {
			System.out.println("Test Scott-Vanstone 1992 signature.");
			// keyGen
			KeyPair keyPair = CommonUtils.initKey(EC_STRING, CURVE_NAME);
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("privateKey length = " + Hex.encodeHexString(privateKey.getEncoded()).length());

			System.out.println("========================================");
			System.out.println("Test signer functionality");

			// signature
			byte[] sign = ECDSASigner.signECDSA(privateKey, "message".getBytes("UTF-8"));
			String singHex = Hex.encodeHexString(sign);
			System.out.println("Hex signature: " + singHex);
			System.out.println("Signature length = " + singHex.length());

			// verify
			if (false == ECDSASigner.verifyECDSA(publicKey, "message".getBytes("UTF-8"), sign)) {
				System.out.println("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}

			System.out.println("ECDSA signer functionality test pass.");

			System.out.println("========================================");
			System.out.println("Test signer parameters serialization & de-serialization.");
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (DecoderException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

}
