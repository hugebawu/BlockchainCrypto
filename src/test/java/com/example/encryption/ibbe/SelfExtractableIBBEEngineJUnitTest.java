package com.example.encryption.ibbe;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.ncepu.crypto.encryption.ibbe.SelfExtractableIBBEEngine;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.IBBEDel07Engine;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/12/5.
 *
 * Self-extractable IBBE engine unit test.
 */
public class SelfExtractableIBBEEngineJUnitTest extends TestCase {
	private static final Logger logger = LoggerFactory.getLogger(SelfExtractableIBBEEngineJUnitTest.class);
	private static final String identity_satisfied = "ID_0";
	private static final String identity_unsatisfied = "ID_9";

	private static final String[] identitySet1 = { "ID_0" };
	private static final String[] identitySet2 = { "ID_2", "ID_3", "ID_1", "ID_0" };
	private static final String[] identitySet3 = { "ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0" };
	private static final String[] identitySet4 = { "ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0",
			"ID_8" };

	private SelfExtractableIBBEEngine engine;

	private void setEngine(SelfExtractableIBBEEngine engine) {
		this.engine = engine;
	}

	private void try_valid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identity, String[] identitySet) {
		try {
			try_decapsulation(publicKey, masterKey, identity, identitySet);
		} catch (Exception e) {
			logger.info("Valid decapsulation test failed, " + "identity  = " + identity + ", " + "id vector = "
					+ Arrays.toString(identitySet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_invalid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identity, String[] identitySet) {
		try {
			try_decapsulation(publicKey, masterKey, identity, identitySet);
		} catch (InvalidCipherTextException e) {
			// correct if getting there, nothing to do.
		} catch (Exception e) {
			logger.info("Invalid decapsulation test failed, " + "identity  = " + identity + ", " + "id vector = "
					+ Arrays.toString(identitySet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String identity,
			String[] identitySet) throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identity);
		byte[] byteArraySecretKey = PairingUtils.SerCipherParameter(secretKey);
		CipherParameters anSecretKey = PairingUtils.deserCipherParameters(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// SelfKeyGen
		byte[] ek = engine.selfKeyGen();

		// Encryption and serialization
		PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identitySet, ek);
		byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
		PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getHeader();
		byte[] byteArrayCiphertext = PairingUtils.SerCipherParameter(ciphertext);
		CipherParameters anCiphertext = PairingUtils.deserCipherParameters(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identitySet, ciphertext);
		Assert.assertArrayEquals(sessionKey, anSessionKey);
		// SelfDecapsulation
		byte[] anSelfSessionKey = engine.selfDecapsulation(ek, ciphertext);
		Assert.assertArrayEquals(sessionKey, anSelfSessionKey);
	}

	private void runAllTests(PairingParameters pairingParameters) {
		try {
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters, identitySet4.length);
			PairingKeySerParameter publicKey = keyPair.getPublic();
			byte[] byteArrayPublicKey = PairingUtils.SerCipherParameter(publicKey);
			CipherParameters anPublicKey = PairingUtils.deserCipherParameters(byteArrayPublicKey);
			Assert.assertEquals(publicKey, anPublicKey);
			publicKey = (PairingKeySerParameter) anPublicKey;

			PairingKeySerParameter masterKey = keyPair.getPrivate();
			byte[] byteArrayMasterKey = PairingUtils.SerCipherParameter(masterKey);
			CipherParameters anMasterKey = PairingUtils.deserCipherParameters(byteArrayMasterKey);
			Assert.assertEquals(masterKey, anMasterKey);
			masterKey = (PairingKeySerParameter) anMasterKey;

			// test valid example
			logger.info("Test valid examples");
			try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet1);
			try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet2);
			try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet3);
			try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet4);

			// test valid example
			logger.info("Test invalid examples");
			try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet1);
			try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet2);
			try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet3);
			try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet4);
			logger.info(engine.getEngineName() + " test passed");
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

	public void testSEIBBEEngineBaseCase() {
		Digest digest = new SHA256Digest();
		IBBEEngine ibbeEngine = IBBEDel07Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
		SelfExtractableIBBEEngine engine = new SelfExtractableIBBEEngine(ibbeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBBEEngineJUnitTest();
		engineJUnitTest.setEngine(engine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBBEEngineWithPKCS5S2() {
		Digest digest = new SHA256Digest();
		IBBEEngine ibbeEngine = IBBEDel07Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S2ParametersGenerator(digest);
		SelfExtractableIBBEEngine engine = new SelfExtractableIBBEEngine(ibbeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBBEEngineJUnitTest();
		engineJUnitTest.setEngine(engine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBBEEngineWithPKCS12() {
		Digest digest = new SHA256Digest();
		IBBEEngine ibbeEngine = IBBEDel07Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS12ParametersGenerator(digest);
		SelfExtractableIBBEEngine engine = new SelfExtractableIBBEEngine(ibbeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBBEEngineJUnitTest();
		engineJUnitTest.setEngine(engine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBBEEngineWithSHA512() {
		Digest digest = new SHA512Digest();
		IBBEEngine ibbeEngine = IBBEDel07Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
		SelfExtractableIBBEEngine engine = new SelfExtractableIBBEEngine(ibbeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBBEEngineJUnitTest();
		engineJUnitTest.setEngine(engine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}
}
