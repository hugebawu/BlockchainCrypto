package com.example.encryption.abe;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.access.AccessPolicyExamples;

import cn.edu.ncepu.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.ncepu.crypto.access.parser.ParserUtils;
import cn.edu.ncepu.crypto.access.tree.AccessTreeEngine;
import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.SecurePrimeSerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.OOKPABEEngine;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.gpsw06a.KPABEGPSW06aEngine;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.gpsw06b.KPABEGPSW06bEngine;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.hw14.OOKPABEHW14Engine;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.llw14.KPABELLW14Engine;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.llw16.OOKPABELLW16Engine;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.rw13.KPABERW13Engine;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * KP-ABE engine test.
 */
public class KPABEEngineJUnitTest extends TestCase {
	private static Logger logger = LoggerFactory.getLogger(KPABEEngineJUnitTest.class);
	private KPABEEngine engine;

	private void try_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, final String accessPolicyString, final String[] attributes) {
		try {
			int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
			String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
			try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
		} catch (Exception e) {
			logger.info("Access policy satisfied test failed, " + "access policy = " + accessPolicyString + ", "
					+ "attributes = " + Arrays.toString(attributes));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, final int[][] accessPolicy, final String[] rhos,
			final String[] attributes) {
		try {
			try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
		} catch (Exception e) {
			logger.info("Access policy satisfied test failed, " + "attributes = " + Arrays.toString(attributes));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, final String accessPolicyString, final String[] attributes) {
		try {
			int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
			String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
			try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
		} catch (InvalidCipherTextException e) {
			// correct, expected exception, nothing to do.
		} catch (Exception e) {
			logger.info("Access policy satisfied test failed, " + "access policy = " + accessPolicyString + ", "
					+ "attributes = " + Arrays.toString(attributes));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, final int[][] accessPolicy, final String[] rhos,
			final String[] attributes) {
		try {
			try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
		} catch (InvalidCipherTextException e) {
			// correct, expected exception, nothing to do.
		} catch (InvalidParameterException e) {
			// correct, expected exception, nothing to do.
		} catch (Exception e) {
			logger.info("Access policy satisfied test failed, " + "attributes = " + Arrays.toString(attributes));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			final int[][] accessPolicy, final String[] rhos, final String[] attributes)
			throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, accessPolicy, rhos);
		byte[] byteArraySecretKey = PairingUtils.SerCipherParameter(secretKey);
		CipherParameters anSecretKey = PairingUtils.deserCipherParameters(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// Encryption and serialization
		Element message = pairing.getGT().newRandomElement().getImmutable();
		PairingCipherSerParameter ciphertext = engine.encryption(publicKey, attributes, message);
		byte[] byteArrayCiphertext = PairingUtils.SerCipherParameter(ciphertext);
		CipherParameters anCiphertext = PairingUtils.deserCipherParameters(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		Element anMessage = engine.decryption(publicKey, secretKey, attributes, ciphertext);
		Assert.assertEquals(message, anMessage);

		// Encapsulation and serialization
		PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, attributes);
		byte[] sessionKey = encapsulationPair.getSessionKey();
		PairingCipherSerParameter header = encapsulationPair.getHeader();
		byte[] byteArrayHeader = PairingUtils.SerCipherParameter(header);
		CipherParameters anHeader = PairingUtils.deserCipherParameters(byteArrayHeader);
		Assert.assertEquals(header, anHeader);
		header = (PairingCipherSerParameter) anHeader;

		// Decryption
		byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, attributes, header);
		Assert.assertArrayEquals(sessionKey, anSessionKey);

		if (this.engine instanceof OOKPABEEngine) {
			OOKPABEEngine ooEngine = (OOKPABEEngine) this.engine;
			// offline encryption and serialization
			PairingCipherSerParameter intermediate = ooEngine.offlineEncryption(publicKey, rhos.length);
			byte[] byteArrayIntermediate = PairingUtils.SerCipherParameter(intermediate);
			CipherParameters anIntermediate = PairingUtils.deserCipherParameters(byteArrayIntermediate);
			Assert.assertEquals(intermediate, anIntermediate);
			intermediate = (PairingCipherSerParameter) anIntermediate;

			// Encryption and serialization
			ciphertext = ooEngine.encryption(publicKey, intermediate, attributes, message);
			byteArrayCiphertext = PairingUtils.SerCipherParameter(ciphertext);
			anCiphertext = PairingUtils.deserCipherParameters(byteArrayCiphertext);
			Assert.assertEquals(ciphertext, anCiphertext);
			ciphertext = (PairingCipherSerParameter) anCiphertext;

			// Decryption
			anMessage = engine.decryption(publicKey, secretKey, attributes, ciphertext);
			Assert.assertEquals(message, anMessage);

			// Encapsulation and serialization
			encapsulationPair = ooEngine.encapsulation(publicKey, intermediate, attributes);
			sessionKey = encapsulationPair.getSessionKey();
			header = encapsulationPair.getHeader();
			byteArrayHeader = PairingUtils.SerCipherParameter(header);
			anHeader = PairingUtils.deserCipherParameters(byteArrayHeader);
			Assert.assertEquals(header, anHeader);
			header = (PairingCipherSerParameter) anHeader;

			// Decapsulation
			anSessionKey = engine.decapsulation(publicKey, secretKey, attributes, header);
			Assert.assertArrayEquals(sessionKey, anSessionKey);
		}
	}

	public void runAllTests(PairingParameters pairingParameters) {
		try {
			Pairing pairing = PairingFactory.getPairing(pairingParameters);
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters, 50);
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

			// test examples
			logger.info("Test example 1");
			try_valid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_1,
					AccessPolicyExamples.access_policy_example_1_satisfied_1);
			try_valid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_1,
					AccessPolicyExamples.access_policy_example_1_satisfied_2);
			try_invalid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_1,
					AccessPolicyExamples.access_policy_example_1_unsatisfied_1);

			// test example 2
			logger.info("Test example 2");
			try_valid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_2,
					AccessPolicyExamples.access_policy_example_2_satisfied_1);
			try_valid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_2,
					AccessPolicyExamples.access_policy_example_2_satisfied_2);
			try_invalid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_2,
					AccessPolicyExamples.access_policy_example_2_unsatisfied_1);
			try_invalid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_2,
					AccessPolicyExamples.access_policy_example_2_unsatisfied_2);
			try_invalid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_2,
					AccessPolicyExamples.access_policy_example_2_unsatisfied_3);

			// test example 3
			logger.info("Test example 3");
			try_valid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_3,
					AccessPolicyExamples.access_policy_example_3_satisfied_1);
			try_invalid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_3,
					AccessPolicyExamples.access_policy_example_3_unsatisfied_1);
			try_invalid_access_policy(pairing, publicKey, masterKey, AccessPolicyExamples.access_policy_example_3,
					AccessPolicyExamples.access_policy_example_3_unsatisfied_2);

			if (engine.isAccessControlEngineSupportThresholdGate()) {
				// test threshold example 1
				logger.info("Test threshold example 1");
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied01);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied02);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied03);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied04);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied05);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied06);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied07);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied08);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied09);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied10);
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_satisfied11);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied01);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied02);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied03);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied04);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied05);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied06);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied07);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied08);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_1_tree,
						AccessPolicyExamples.access_policy_threshold_example_1_rho,
						AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied09);

				// test threshold example 2
				logger.info("Test threshold example 2");
				try_valid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_2_tree,
						AccessPolicyExamples.access_policy_threshold_example_2_rho,
						AccessPolicyExamples.access_policy_threshold_example_2_satisfied01);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_2_tree,
						AccessPolicyExamples.access_policy_threshold_example_2_rho,
						AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied01);
				try_invalid_access_policy(pairing, publicKey, masterKey,
						AccessPolicyExamples.access_policy_threshold_example_2_tree,
						AccessPolicyExamples.access_policy_threshold_example_2_rho,
						AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied02);
			}
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

	public void testKPABEGPSW06aEngine() {
		this.engine = KPABEGPSW06aEngine.getInstance();
		logger.info("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
		engine.setAccessControlEngine(AccessTreeEngine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

		logger.info("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
		engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testKPABEGPSW06bEngine() {
		this.engine = KPABEGPSW06bEngine.getInstance();
		logger.info("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
		engine.setAccessControlEngine(AccessTreeEngine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

		logger.info("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
		engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testKPABERW13Engine() {
		this.engine = KPABERW13Engine.getInstance();
		logger.info("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
		engine.setAccessControlEngine(AccessTreeEngine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

		logger.info("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
		engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testKPABEHW14Engine() {
		this.engine = OOKPABEHW14Engine.getInstance();
		logger.info("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
		engine.setAccessControlEngine(AccessTreeEngine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

		logger.info("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
		engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testKPABELLW14Engine() {
		this.engine = KPABELLW14Engine.getInstance();
		logger.info("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
		engine.setAccessControlEngine(AccessTreeEngine.getInstance());

		ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
		AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
		KeyGenerationParameters keyGenerationParameters = new DLogKR00bKeyGenerationParameters(new SecureRandom(),
				SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);
		((KPABELLW14Engine) this.engine).setChameleonHasher(chameleonHasher, chKeyPairGenerator,
				keyGenerationParameters);
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

		logger.info("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
		engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testKPABELLW16Engine() {
		this.engine = OOKPABELLW16Engine.getInstance();
		logger.info("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
		engine.setAccessControlEngine(AccessTreeEngine.getInstance());

		ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()),
				new SHA256Digest());
		AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
		KeyGenerationParameters keyGenerationParameters = new DLogKR00bKeyGenerationParameters(new SecureRandom(),
				SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);
		((OOKPABELLW16Engine) this.engine).setChameleonHasher(chameleonHasher, chKeyPairGenerator,
				keyGenerationParameters);
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

		logger.info("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
		engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}
}
