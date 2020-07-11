/**
 * 
 */
package com.example.HE.ibeHE;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.HE.ibeHE.IBEHEEngine;
import cn.edu.ncepu.crypto.HE.ibeHE.bf01aHE.BF01aHEEngine;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 8, 2020 11:47:24 AM
 * @ClassName IBEHEEngineTest
 * @Description: TODO(IBE-based homomorphic encryption engine test.)
 */
public class IBEHEEngineTest {
	private static Logger logger = LoggerFactory.getLogger(IBEHEEngineTest.class);
	private static final String identity_1 = "ID_1";
	private static final String identity_2 = "ID_2";
	private PairingParameters pairingParams = null;

	private IBEHEEngine engine;

	private void try_valid_enc_dec(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext) {
		try {
			try_enc_dec(pairing, publicKey, masterKey, identityForSecretKey, identityForCiphertext);
		} catch (Exception e) {
			logger.info("Valid decryption test failed, " + "secret key identity  = " + identityForSecretKey + ", "
					+ "ciphertext identity = " + identityForCiphertext);
			logger.info(e.getLocalizedMessage());
		}
	}

	private void try_invalid_enc_dec(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String identityForSecretKey, String identityForCiphertext) {
		try {
			try_enc_dec(pairing, publicKey, masterKey, identityForSecretKey, identityForCiphertext);
		} catch (InvalidCipherTextException e) {
			logger.info(e.getLocalizedMessage());
			logger.info("Invalid decryption test passed!, " + "secret key identity  = " + identityForSecretKey + ", "
					+ "ciphertext identity = " + identityForCiphertext);
		} catch (ClassNotFoundException e) {
			logger.info(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.info(e.getLocalizedMessage());
		}
	}

	private void try_enc_dec(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext)
			throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.extract(identityForSecretKey, masterKey);
		byte[] byteArraySecretKey = PairingUtils.SerCipherParameter(secretKey);
		CipherParameters anSecretKey = PairingUtils.deserCipherParameters(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// Encryption and serialization
		// the message waits to be encrypted
		String plainMessage = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
		logger.info("plaintext message: " + plainMessage);
		Element message = PairingUtils.mapNumStringToElement(pairing, plainMessage, PairingGroupType.GT);
		PairingCipherSerParameter ciphertext = engine.encrypt(publicKey, identityForCiphertext, message);
		byte[] byteArrayCiphertext = PairingUtils.SerCipherParameter(ciphertext);
		CipherParameters anCiphertext = PairingUtils.deserCipherParameters(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		Element anMessage = engine.decrypt(secretKey, identityForCiphertext, ciphertext);
		String decMessage = PairingUtils.mapElementToNumString(anMessage);
		logger.info("decrypted message: " + decMessage);
		// new String(anMessage.toBigInteger().toByteArray(), "UTF-8"));
		Assert.assertEquals(plainMessage, decMessage);
	}

	private void runAllTests(PairingParameters pairingParameters) {
		// 初始化Pairing
		Pairing pairing = PairingFactory.getPairing(pairingParameters);
		try {
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters);
			// get publicKey include (P, Ppub), where Ppub=sP
			PairingKeySerParameter publicKey = keyPair.getPublic();
			byte[] byteArrayPublicKey = PairingUtils.SerCipherParameter(publicKey);
			CipherParameters anPublicKey = PairingUtils.deserCipherParameters(byteArrayPublicKey);
			Assert.assertEquals(publicKey, anPublicKey);
			publicKey = (PairingKeySerParameter) anPublicKey;

			// get master-key s
			PairingKeySerParameter masterKey = keyPair.getPrivate();
			byte[] byteArrayMasterKey = PairingUtils.SerCipherParameter(masterKey);
			CipherParameters anMasterKey = PairingUtils.deserCipherParameters(byteArrayMasterKey);
			Assert.assertEquals(masterKey, anMasterKey);
			masterKey = (PairingKeySerParameter) anMasterKey;

			// test valid example
			logger.info("Test valid examples");
			try_valid_enc_dec(pairing, publicKey, masterKey, identity_1, identity_1);
			try_valid_enc_dec(pairing, publicKey, masterKey, identity_2, identity_2);
			logger.info("");

			// test invalid example
			logger.info("Test invalid examples");
			try_invalid_enc_dec(pairing, publicKey, masterKey, identity_1, identity_2);
			try_invalid_enc_dec(pairing, publicKey, masterKey, identity_2, identity_1);
			logger.info("");
			logger.info(engine.getEngineName() + " test passed!");
		} catch (ClassNotFoundException e) {
			logger.info("setup test failed.");
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			logger.info("setup test failed.");
			e.printStackTrace();
			System.exit(1);
		}
	}

	@Ignore
	@Test
	public void testBF01aHEEngine() {
		this.engine = BF01aHEEngine.getInstance();
		// Type A 对称质数阶双线性群
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		runAllTests(pairingParams);
	}

	@Ignore
	@Test
	// 经验证只有乘法同态性质
	public void testHomomorphism() {
		this.engine = BF01aHEEngine.getInstance();
		// Type A 对称质数阶双线性群
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		runHomomorphismTest(pairingParams);
	}

	private void runHomomorphismTest(PairingParameters pairingParameters) {
		// 初始化Pairing
		Pairing pairing = PairingFactory.getPairing(pairingParameters);
		PairingKeySerPair keyPair = engine.setup(pairingParameters);
		// get system publicKey include (P, Ppub), where Ppub=sP
		PairingKeySerParameter publicKey = keyPair.getPublic();
		// get system masterkey s
		PairingKeySerParameter masterKey = keyPair.getPrivate();

		String topLayerAdmin = "TopLayerAdmin";
		// topLayerAdmin secret key extract
		PairingKeySerParameter secretKey = engine.extract(topLayerAdmin, masterKey);

		try {
			Map<String, PairingCipherSerParameter> ciphertextMap = new LinkedHashMap<String, PairingCipherSerParameter>();

			// user1_org1 collect, encrypt and report data
			String num_user1_org1 = "11";

			BigInteger qt = new BigInteger("2").pow(pairing.getPairingPreProcessingLengthInBytes());
			BigInteger q = pairingParameters.getBigInteger("q");
			Element e_num_user1_org1 = PairingUtils.mapNumStringToElement(pairing, num_user1_org1, PairingGroupType.GT);
			PairingCipherSerParameter ciphertext_user1_org1 = engine.encrypt(publicKey, topLayerAdmin,
					e_num_user1_org1);
			ciphertextMap.put("user1_org1", ciphertext_user1_org1);

			// user2_org1 collect, encrypt and report data
			String num_user2_org1 = "21";
			Element e_num_user2_org1 = PairingUtils.mapNumStringToElement(pairing, num_user2_org1, PairingGroupType.GT);
			PairingCipherSerParameter ciphertext_user2_org1 = engine.encrypt(publicKey, topLayerAdmin,
					e_num_user2_org1);
			ciphertextMap.put("user2_org1", ciphertext_user2_org1);

			// org1 aggregator aggregate the ciphertext of user1_org1 and user2_org1
			PairingCipherSerParameter ciphertext_org1 = engine.add(publicKey, ciphertextMap);

			// if org1 aggregator knows the secretKey, he can conduct the Decryption
			Element e_num_org1 = engine.decrypt(secretKey, topLayerAdmin, ciphertext_org1);

			// IBEHE(a*b) = IBEHE(a)+IBEHE(b)
			assertTrue(e_num_org1.isEqual(e_num_user1_org1.mul(e_num_user2_org1)));
//-----------------------------------------------------------------------------------------------------------
			// user1_org2 collect, encrypt and report data
			String num_user1_org2 = "12";
			Element e_num_user1_org2 = PairingUtils.mapNumStringToElement(pairing, num_user1_org2, PairingGroupType.GT);
			PairingCipherSerParameter ciphertext_user1_org2 = engine.encrypt(publicKey, topLayerAdmin,
					e_num_user1_org2);

			// user2_org2 collect, encrypt and report data
			String num_user2_org2 = "22";
			Element e_num_user2_org2 = PairingUtils.mapNumStringToElement(pairing, num_user2_org2, PairingGroupType.GT);
			PairingCipherSerParameter ciphertext_user2_org2 = engine.encrypt(publicKey, topLayerAdmin,
					e_num_user2_org2);

		} catch (InvalidCipherTextException e) {
			logger.info("Valid decryption test failed, " + "secret key identity  = " + topLayerAdmin + ", "
					+ "ciphertext identity = " + topLayerAdmin);
			logger.info(e.getLocalizedMessage());
		}
	}
}
