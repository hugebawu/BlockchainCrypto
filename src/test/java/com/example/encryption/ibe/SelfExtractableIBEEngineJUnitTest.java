package com.example.encryption.ibe;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.IBEEngine;
import cn.edu.ncepu.crypto.encryption.ibe.SelfExtractableIBEEngine;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.IBEBF01aEngine;
import cn.edu.ncepu.crypto.encryption.ibe.gen06a.IBEGen06aEngine;
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

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Self-extractable IBE engine junit test.
 */
public class SelfExtractableIBEEngineJUnitTest extends TestCase {
	private static final Logger logger = LoggerFactory.getLogger(SelfExtractableIBEEngineJUnitTest.class);
	private static final String identity_1 = "ID_1";
	private static final String identity_2 = "ID_2";

	private SelfExtractableIBEEngine engine;

	public void setEngine(SelfExtractableIBEEngine seIBEEngine) {
		this.engine = seIBEEngine;
	}

	private void try_valid_decryption(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext) {
		try {
			try_decryption(publicKey, masterKey, identityForSecretKey, identityForCiphertext);
		} catch (Exception e) {
			logger.info("Valid decryption test failed, " + "secret key identity  = " + identityForSecretKey + ", "
					+ "ciphertext identity = " + identityForCiphertext);
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_invalid_decryption(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext) {
		try {
			try_decryption(publicKey, masterKey, identityForSecretKey, identityForCiphertext);
		} catch (InvalidCipherTextException e) {
			// correct if getting there, nothing to do.
		} catch (Exception e) {
			logger.info("Invalid decryption test failed, " + "secret key identity  = " + identityForSecretKey + ", "
					+ "ciphertext identity = " + identityForCiphertext);
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_decryption(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext)
			throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityForSecretKey);
		byte[] byteArraySecretKey = CommonUtils.SerObject(secretKey);
		CipherParameters anSecretKey = (CipherParameters) CommonUtils.deserObject(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// self KeyGen
		byte[] ek = engine.selfKeyGen();

		// Encapsulation and serialization
		PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityForCiphertext, ek);
		byte[] sessionKey = encapsulationPair.getSessionKey();
		PairingCipherSerParameter header = encapsulationPair.getHeader();
		byte[] byteArrayHeader = CommonUtils.SerObject(header);
		CipherParameters anHeader = (CipherParameters) CommonUtils.deserObject(byteArrayHeader);
		Assert.assertEquals(header, anHeader);
		header = (PairingCipherSerParameter) anHeader;

		// Decapsulation
		byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityForCiphertext, header);
		Assert.assertArrayEquals(sessionKey, anSessionKey);
		// Self decapsulation
		byte[] anSelfSessionKey = engine.selfDecapsulation(ek, header);
		Assert.assertArrayEquals(sessionKey, anSelfSessionKey);
	}

	public void runAllTests(PairingParameters pairingParameters) {
		try {
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters);
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
			try_valid_decryption(publicKey, masterKey, identity_1, identity_1);
			try_valid_decryption(publicKey, masterKey, identity_2, identity_2);

			// test valid example
			logger.info("Test invalid examples");
			try_invalid_decryption(publicKey, masterKey, identity_1, identity_2);
			try_invalid_decryption(publicKey, masterKey, identity_2, identity_1);
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

	public void testSEIBEEngineBaseCase() {
		Digest digest = new SHA256Digest();
		IBEEngine ibeEngine = IBEGen06aEngine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
		SelfExtractableIBEEngine seIBEEngine = new SelfExtractableIBEEngine(ibeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBEEngineJUnitTest();
		engineJUnitTest.setEngine(seIBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBEEngineWithBF01a() {
		Digest digest = new SHA256Digest();
		IBEEngine ibeEngine = IBEBF01aEngine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
		SelfExtractableIBEEngine seIBEEngine = new SelfExtractableIBEEngine(ibeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBEEngineJUnitTest();
		engineJUnitTest.setEngine(seIBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBEEngineWithPKCS5S2() {
		Digest digest = new SHA256Digest();
		IBEEngine ibeEngine = IBEGen06aEngine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S2ParametersGenerator(digest);
		SelfExtractableIBEEngine seIBEEngine = new SelfExtractableIBEEngine(ibeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBEEngineJUnitTest();
		engineJUnitTest.setEngine(seIBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBEEngineWithPKCS12() {
		Digest digest = new SHA256Digest();
		IBEEngine ibeEngine = IBEGen06aEngine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS12ParametersGenerator(digest);
		SelfExtractableIBEEngine seIBEEngine = new SelfExtractableIBEEngine(ibeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBEEngineJUnitTest();
		engineJUnitTest.setEngine(seIBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testSEIBEEngineWithSHA512() {
		Digest digest = new SHA512Digest();
		IBEEngine ibeEngine = IBEGen06aEngine.getInstance();
		BlockCipher blockCipher = new AESEngine();
		PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
		SelfExtractableIBEEngine seIBEEngine = new SelfExtractableIBEEngine(ibeEngine, pbeParametersGenerator,
				blockCipher, digest);
		SelfExtractableIBEEngineJUnitTest engineJUnitTest = new SelfExtractableIBEEngineJUnitTest();
		engineJUnitTest.setEngine(seIBEEngine);
		engineJUnitTest
				.runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}
}
