package com.example.encryption.hibbe;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.HIBBELLW16bEngine;
import cn.edu.ncepu.crypto.encryption.hibbe.llw17.HIBBELLW17Engine;
import cn.edu.ncepu.crypto.signature.pks.PairingDigestSigner;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08Signer;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE engine test procedures. All instances should pass this unit test.
 */
public class HIBBEEngineJUnitTest extends TestCase {
	private static final Logger logger = LoggerFactory.getLogger(HIBBEEngineJUnitTest.class);
	private static final String[] identityVector4_satisfied = { null, null, null, "ID_4", null, null, null, null };
	private static final String[] identityVector46_satisfied = { null, null, null, "ID_4", null, "ID_6", null, null };
	private static final String[] identityVector467_satisfied = { null, null, null, "ID_4", null, "ID_6", "ID_7",
			null };
	private static final String[] identityVector45_unsatisfied = { null, null, null, "ID_4", "ID_5", null, null, null };
	private static final String[] identityVector3_unsatisfied = { "ID_3", null, null, null, null, null, null, null };
	private static final String[] identityVector31_unsatisfied = { "ID_3", null, "ID_1", null, null, null, null, null };
	private static final String[] identityVectorSet13467 = { "ID_1", null, "ID_3", "ID_4", null, "ID_6", "ID_7", null };

	private HIBBEEngine engine;

	private void try_valid_decryption(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String[] identityVector, String[] identityVectorSet) {
		try {
			try_decryption(pairing, publicKey, masterKey, identityVector, identityVectorSet);
		} catch (Exception e) {
			logger.info("Valid decryption test failed, " + "identity vector = " + Arrays.toString(identityVector) + ", "
					+ "identity v. set = " + Arrays.toString(identityVectorSet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_delegation_valid_decryption(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String[] identityVector, int index, String delegateId,
			String[] identityVectorSet) {
		try {
			PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
			PairingKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, index, delegateId);
			byte[] byteArrayDelegateKey = CommonUtils.SerObject(delegateKey);
			CipherParameters anDelegateKey = (CipherParameters) CommonUtils.deserObject(byteArrayDelegateKey);
			Assert.assertEquals(delegateKey, anDelegateKey);
			delegateKey = (PairingKeySerParameter) anDelegateKey;

			// Encryption and serialization
			Element message = pairing.getGT().newRandomElement().getImmutable();
			PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorSet, message);
			byte[] byteArrayCiphertext = CommonUtils.SerObject(ciphertext);
			CipherParameters anCiphertext = (CipherParameters) CommonUtils.deserObject(byteArrayCiphertext);
			Assert.assertEquals(ciphertext, anCiphertext);
			ciphertext = (PairingCipherSerParameter) anCiphertext;

			// Decryption
			Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorSet, ciphertext);
			Assert.assertEquals(message, anMessage);

			// Encapsulation and serialization
			PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorSet);
			byte[] sessionKey = encapsulationPair.getSessionKey();
			PairingCipherSerParameter header = encapsulationPair.getHeader();
			byte[] byteArrayHeader = CommonUtils.SerObject(header);
			CipherParameters anHeader = (CipherParameters) CommonUtils.deserObject(byteArrayHeader);
			Assert.assertEquals(header, anHeader);
			header = (PairingCipherSerParameter) anHeader;

			// Decapsulation
			byte[] anSessionKey = engine.decapsulation(publicKey, delegateKey, identityVectorSet, header);
			Assert.assertArrayEquals(sessionKey, anSessionKey);
		} catch (Exception e) {
			logger.info("Valid decryption decryption test failed, " + "identity vector = "
					+ Arrays.toString(identityVector) + ", " + "delegate ident. = " + delegateId + ", "
					+ "identity v. set = " + Arrays.toString(identityVectorSet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_invalid_decryption(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String[] identityVector, String[] identityVectorSet) {
		try {
			try_decryption(pairing, publicKey, masterKey, identityVector, identityVectorSet);
		} catch (InvalidCipherTextException e) {
			// correct if getting there, nothing to do.
		} catch (Exception e) {
			logger.info("Invalid decryption test failed, " + "identity vector = " + Arrays.toString(identityVector)
					+ ", " + "identity v. set = " + Arrays.toString(identityVectorSet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_delegation_invalid_decryption(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String[] identityVector, String[] identityVectorSet) {
		try {
			PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
			PairingKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, 2, "ID_1");
			byte[] byteArrayDelegateKey = CommonUtils.SerObject(delegateKey);
			CipherParameters anDelegateKey = (CipherParameters) CommonUtils.deserObject(byteArrayDelegateKey);
			Assert.assertEquals(delegateKey, anDelegateKey);
			delegateKey = (PairingKeySerParameter) anDelegateKey;

			// Encryption and serialization
			Element message = pairing.getGT().newRandomElement().getImmutable();
			PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorSet, message);
			byte[] byteArrayCiphertext = CommonUtils.SerObject(ciphertext);
			CipherParameters anCiphertext = (CipherParameters) CommonUtils.deserObject(byteArrayCiphertext);
			Assert.assertEquals(ciphertext, anCiphertext);
			ciphertext = (PairingCipherSerParameter) anCiphertext;

			// Decryption
			Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorSet, ciphertext);
			Assert.assertEquals(message, anMessage);

			// Encapsulation and serialization
			PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorSet);
			byte[] sessionKey = encapsulationPair.getSessionKey();
			PairingCipherSerParameter header = encapsulationPair.getHeader();
			byte[] byteArrayHeader = CommonUtils.SerObject(header);
			CipherParameters anHeader = (CipherParameters) CommonUtils.deserObject(byteArrayHeader);
			Assert.assertEquals(header, anHeader);
			header = (PairingCipherSerParameter) anHeader;

			// Decapsulation
			byte[] anSessionKey = engine.decapsulation(publicKey, delegateKey, identityVectorSet, header);
			Assert.assertArrayEquals(sessionKey, anSessionKey);
		} catch (InvalidCipherTextException e) {
			// correct if getting there, nothing to do.
		} catch (Exception e) {
			logger.info("Invalid delegate decryption test failed, " + "identity vector = "
					+ Arrays.toString(identityVector) + ", " + "delegate ident. = " + "ID_1" + ", "
					+ "identity v. set = " + Arrays.toString(identityVectorSet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String[] identityVector, String[] identityVectorSet)
			throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
		byte[] byteArraySecretKey = CommonUtils.SerObject(secretKey);
		CipherParameters anSecretKey = (CipherParameters) CommonUtils.deserObject(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// Encryption and serialization
		Element message = pairing.getGT().newRandomElement().getImmutable();
		PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorSet, message);
		byte[] byteArrayCiphertext = CommonUtils.SerObject(ciphertext);
		CipherParameters anCiphertext = (CipherParameters) CommonUtils.deserObject(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		Element anMessage = engine.decryption(publicKey, secretKey, identityVectorSet, ciphertext);
		Assert.assertEquals(message, anMessage);

		// Encapsulation and serialization
		PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorSet);
		byte[] sessionKey = encapsulationPair.getSessionKey();
		PairingCipherSerParameter header = encapsulationPair.getHeader();
		byte[] byteArrayHeader = CommonUtils.SerObject(header);
		CipherParameters anHeader = (CipherParameters) CommonUtils.deserObject(byteArrayHeader);
		Assert.assertEquals(header, anHeader);
		header = (PairingCipherSerParameter) anHeader;

		// Decapsulation
		byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorSet, header);
		Assert.assertArrayEquals(sessionKey, anSessionKey);
	}

	private void runAllTests(PairingParameters pairingParameters) {
		Pairing pairing = PairingFactory.getPairing(pairingParameters);
		try {
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters, identityVectorSet13467.length);
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
			try_valid_decryption(pairing, publicKey, masterKey, identityVector4_satisfied, identityVectorSet13467);
			try_valid_decryption(pairing, publicKey, masterKey, identityVector46_satisfied, identityVectorSet13467);
			try_valid_decryption(pairing, publicKey, masterKey, identityVector467_satisfied, identityVectorSet13467);
			try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector4_satisfied, 5, "ID_6",
					identityVectorSet13467);
			try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector46_satisfied, 6, "ID_7",
					identityVectorSet13467);

			// test valid example
			logger.info("Test invalid examples");
			try_invalid_decryption(pairing, publicKey, masterKey, identityVector45_unsatisfied, identityVectorSet13467);
			try_invalid_decryption(pairing, publicKey, masterKey, identityVector3_unsatisfied, identityVectorSet13467);
			try_invalid_decryption(pairing, publicKey, masterKey, identityVector31_unsatisfied, identityVectorSet13467);
			try_delegation_invalid_decryption(pairing, publicKey, masterKey, identityVector3_unsatisfied,
					identityVectorSet13467);

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

	public void testHIBBELLW14Engine() {
		this.engine = HIBBELLW14Engine.getInstance();
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
	}

	public void testHIBBELLW16aEngine() {
		this.engine = HIBBELLW16aEngine.getInstance();
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testHIBBELLW16bEngine() {
		this.engine = HIBBELLW16bEngine.getInstance();
		Signer signer = new PairingDigestSigner(new BB08Signer(), new SHA256Digest());
		PairingKeyPairGenerator signKeyPairGenerator = new BB08SignKeyPairGenerator();
		BB08SignKeyPairGenerationParameter signKeyPairGenerationParameter = new BB08SignKeyPairGenerationParameter(
				PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512));
		((HIBBELLW16bEngine) this.engine).setSigner(signer, signKeyPairGenerator, signKeyPairGenerationParameter);
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testHIBBELLW17Engine() {
		this.engine = HIBBELLW17Engine.getInstance();
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
	}
}
