package com.example.encryption.be;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.be.BEEngine;
import cn.edu.ncepu.crypto.encryption.be.SelfExtractableBEEngine;
import cn.edu.ncepu.crypto.encryption.be.bgw05.BEBGW05Engine;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
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

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Self-extractable BE unit test.
 */
public class SelfExtractableBEEngineJUnitTest extends TestCase {
	private static final Logger logger = LoggerFactory.getLogger(SelfExtractableBEEngineJUnitTest.class);
	private static final int maxNumUser = 8;
	private static final int index1_valid = 1;
	private static final int index8_valid = 8;
	private static final int index6_invalid = 6;
	private static final int index0_invalid = 0;
	private static final int index9_invalid = 9;

	private static final int[] indexSet1;
	private static final int[] indexSet2;
	private static final int[] indexSet3;

	static {
		indexSet1 = new int[] { 1 };
		indexSet2 = new int[] { 1, 2, 5, 7, 8 };
		indexSet3 = new int[] { 1, 1, 5, 2, 2, 5, 8, 7, 7 };
	}

	private SelfExtractableBEEngine engine;

	public void setEngine(SelfExtractableBEEngine engine) {
		this.engine = engine;
	}

	private void try_valid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int index,
			int[] indexSet) {
		try {
			try_decapsulation(publicKey, masterKey, index, indexSet);
		} catch (Exception e) {
			logger.info("Valid decapsulation test failed, " + "index  = " + index + ", " + "indexSet = "
					+ Arrays.toString(indexSet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_invalid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			int index, int[] indexSet) {
		try {
			try_decapsulation(publicKey, masterKey, index, indexSet);
		} catch (InvalidCipherTextException e) {
			// correct if getting there, nothing to do.
		} catch (IllegalArgumentException e) {
			// correct if getting there, nothing to do
		} catch (Exception e) {
			logger.info("Invalid decapsulation test failed, " + "index  = " + index + ", " + "indexSet = "
					+ Arrays.toString(indexSet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int index,
			int[] indexSet) throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, index);
		byte[] byteArraySecretKey = CommonUtils.SerObject(secretKey);
		CipherParameters anSecretKey = (CipherParameters) CommonUtils.deserObject(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// self KeyGen
		byte[] ek = engine.selfKeyGen();

		// Encryption and serialization
		PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, indexSet, ek);
		byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
		PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getHeader();
		byte[] byteArrayCiphertext = CommonUtils.SerObject(ciphertext);
		CipherParameters anCiphertext = (CipherParameters) CommonUtils.deserObject(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, indexSet, ciphertext);
		Assert.assertArrayEquals(sessionKey, anSessionKey);
		// Self decapsulation
		byte[] anSelfSessionKey = engine.selfDecapsulation(ek, ciphertext);
		Assert.assertArrayEquals(sessionKey, anSelfSessionKey);
	}

	public void runAllTests(PairingParameters pairingParameters) {
		try {
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters, maxNumUser);
			PairingKeySerParameter publicKey = keyPair.getPublic();
			byte[] byteArrayPublicKey = CommonUtils.SerObject(publicKey);
			CipherParameters anPublicKey = (CipherParameters) CommonUtils.deserObject(byteArrayPublicKey);
			Assert.assertEquals(publicKey, anPublicKey);
			publicKey = (PairingKeySerParameter) anPublicKey;

			PairingKeySerParameter masterKey = keyPair.getPrivate();
			byte[] byteArrayMasterKey = CommonUtils.SerObject(masterKey);
			CipherParameters anMasterKey = (CipherParameters) CommonUtils.deserObject(byteArrayMasterKey);
			Assert.assertEquals(masterKey, anMasterKey);
			masterKey = (PairingKeySerParameter) anMasterKey;

			// test valid example
			logger.info("Test valid examples");
			try_valid_decapsulation(publicKey, masterKey, index1_valid, indexSet1);
			try_valid_decapsulation(publicKey, masterKey, index1_valid, indexSet2);
			try_valid_decapsulation(publicKey, masterKey, index8_valid, indexSet2);
			try_valid_decapsulation(publicKey, masterKey, index1_valid, indexSet3);
			try_valid_decapsulation(publicKey, masterKey, index8_valid, indexSet3);

			// test valid example
			logger.info("Test invalid examples");
			try_invalid_decapsulation(publicKey, masterKey, index0_invalid, indexSet2);
			try_invalid_decapsulation(publicKey, masterKey, index6_invalid, indexSet2);
			try_invalid_decapsulation(publicKey, masterKey, index9_invalid, indexSet2);
			try_invalid_decapsulation(publicKey, masterKey, index0_invalid, indexSet3);
			try_invalid_decapsulation(publicKey, masterKey, index6_invalid, indexSet3);
			try_invalid_decapsulation(publicKey, masterKey, index9_invalid, indexSet3);
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

	public void testSEBEEngineBaseCase() {
		Digest digest = new SHA256Digest();
		BEEngine beEngine = BEBGW05Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
		SelfExtractableBEEngine seBEEngine = new SelfExtractableBEEngine(beEngine, pbeParametersGenerator, blockCipher,
				digest);
		SelfExtractableBEEngineJUnitTest engineJUnitTest = new SelfExtractableBEEngineJUnitTest();
		engineJUnitTest.setEngine(seBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBEEngineWithPKCS5S2() {
		Digest digest = new SHA256Digest();
		BEEngine beEngine = BEBGW05Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S2ParametersGenerator(digest);
		SelfExtractableBEEngine seBEEngine = new SelfExtractableBEEngine(beEngine, pbeParametersGenerator, blockCipher,
				digest);
		SelfExtractableBEEngineJUnitTest engineJUnitTest = new SelfExtractableBEEngineJUnitTest();
		engineJUnitTest.setEngine(seBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBEEngineWithPKCS12() {
		Digest digest = new SHA256Digest();
		BEEngine beEngine = BEBGW05Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS12ParametersGenerator(digest);
		SelfExtractableBEEngine seBEEngine = new SelfExtractableBEEngine(beEngine, pbeParametersGenerator, blockCipher,
				digest);
		SelfExtractableBEEngineJUnitTest engineJUnitTest = new SelfExtractableBEEngineJUnitTest();
		engineJUnitTest.setEngine(seBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBEEngineWithSHA512() {
		Digest digest = new SHA512Digest();
		BEEngine beEngine = BEBGW05Engine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
		SelfExtractableBEEngine seBEEngine = new SelfExtractableBEEngine(beEngine, pbeParametersGenerator, blockCipher,
				digest);
		SelfExtractableBEEngineJUnitTest engineJUnitTest = new SelfExtractableBEEngineJUnitTest();
		engineJUnitTest.setEngine(seBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}
}
