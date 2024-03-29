package com.example.encryption.hibe;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.HIBEEngine;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * HIBE engine test procedures. All instances should pass this unit test.
 */
public class HIBEEngineJUnitTest extends TestCase {
	private static final Logger logger = LoggerFactory.getLogger(HIBEEngineJUnitTest.class);
	private static final String[] identityVector1 = { "ID_1" };
	private static final String[] identityVector12 = { "ID_1", "ID_2" };
	private static final String[] identityVector123 = { "ID_1", "ID_2", "ID_3" };

	private static final String[] identityVector3 = { "ID_3" };
	private static final String[] identityVector31 = { "ID_3", "ID_1" };
	private static final String[] identityVector132 = { "ID_1", "ID_3", "ID_2" };

	private HIBEEngine engine;

	private void try_valid_decryption(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String[] identityVector, String[] identityVectorSet) {
		try {
			try_decryption(pairing, publicKey, masterKey, identityVector, identityVectorSet);
		} catch (Exception e) {
			logger.info("Valid decryption test failed, " + "identity vector  = " + Arrays.toString(identityVector)
					+ ", " + "iv encapsulation = " + Arrays.toString(identityVectorSet));
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
			logger.info("Invalid decryption test failed, " + "identity vector  = " + Arrays.toString(identityVector)
					+ ", " + "iv encapsulation = " + Arrays.toString(identityVectorSet));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String[] identityVector, String[] identityVectorEnc)
			throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
		byte[] byteArraySecretKey = CommonUtils.SerObject(secretKey);
		CipherParameters anSecretKey = (CipherParameters) CommonUtils.deserObject(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// Encryption and serialization
		Element message = pairing.getGT().newRandomElement().getImmutable();
		PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorEnc, message);
		byte[] byteArrayCiphertext = CommonUtils.SerObject(ciphertext);
		CipherParameters anCiphertext = (CipherParameters) CommonUtils.deserObject(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		Element anMessage = engine.decryption(publicKey, secretKey, identityVectorEnc, ciphertext);
		Assert.assertEquals(message, anMessage);

		// Encapsulation and serialization
		PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorEnc);
		byte[] sessionKey = encapsulationPair.getSessionKey();
		PairingCipherSerParameter header = encapsulationPair.getHeader();
		byte[] byteArrayHeader = CommonUtils.SerObject(header);
		CipherParameters anHeader = (CipherParameters) CommonUtils.deserObject(byteArrayHeader);
		Assert.assertEquals(anHeader, anHeader);
		header = (PairingCipherSerParameter) anHeader;

		// Decapsulation
		byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorEnc, header);
		Assert.assertArrayEquals(sessionKey, anSessionKey);
	}

	private void try_delegation_valid_decryption(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String[] identityVector, String delegateId, String[] identityVectorEnc) {
		try {
			PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
			PairingKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, delegateId);
			byte[] byteArrayDelegateKey = CommonUtils.SerObject(delegateKey);
			CipherParameters anDelegateKey = (CipherParameters) CommonUtils.deserObject(byteArrayDelegateKey);
			Assert.assertEquals(delegateKey, anDelegateKey);
			delegateKey = (PairingKeySerParameter) anDelegateKey;

			// Encryption and serialization
			Element message = pairing.getGT().newRandomElement().getImmutable();
			PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorEnc, message);
			byte[] byteArrayCiphertext = CommonUtils.SerObject(ciphertext);
			CipherParameters anCiphertext = (CipherParameters) CommonUtils.deserObject(byteArrayCiphertext);
			Assert.assertEquals(ciphertext, anCiphertext);
			ciphertext = (PairingCipherSerParameter) anCiphertext;

			// Decryption
			Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorEnc, ciphertext);
			Assert.assertEquals(message, anMessage);

			// Encapsulation and serialization
			PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorEnc);
			byte[] sessionKey = encapsulationPair.getSessionKey();
			PairingCipherSerParameter header = encapsulationPair.getHeader();
			byte[] byteArrayHeader = CommonUtils.SerObject(header);
			CipherParameters anHeader = (CipherParameters) CommonUtils.deserObject(byteArrayHeader);
			Assert.assertEquals(anHeader, anHeader);
			header = (PairingCipherSerParameter) anHeader;

			// Decapsulation
			byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorEnc, header);
			Assert.assertArrayEquals(sessionKey, anSessionKey);
		} catch (Exception e) {
			logger.info("Valid delegate decryption test failed, " + "identity vector  = "
					+ Arrays.toString(identityVector) + ", " + "delegate ident. = " + delegateId + ", "
					+ "iv encapsulation = " + Arrays.toString(identityVectorEnc));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void try_delegation_invalid_decryption(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String[] identityVector, String delegateId, String[] identityVectorEnc) {
		try {
			PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
			PairingKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, delegateId);
			byte[] byteArrayDelegateKey = CommonUtils.SerObject(delegateKey);
			CipherParameters anDelegateKey = (CipherParameters) CommonUtils.deserObject(byteArrayDelegateKey);
			Assert.assertEquals(delegateKey, anDelegateKey);
			delegateKey = (PairingKeySerParameter) anDelegateKey;

			// Encryption and serialization
			Element message = pairing.getGT().newRandomElement().getImmutable();
			PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorEnc, message);
			byte[] byteArrayCiphertext = CommonUtils.SerObject(ciphertext);
			CipherParameters anCiphertext = (CipherParameters) CommonUtils.deserObject(byteArrayCiphertext);
			Assert.assertEquals(ciphertext, anCiphertext);
			ciphertext = (PairingCipherSerParameter) anCiphertext;

			// Decryption
			Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorEnc, ciphertext);
			Assert.assertEquals(message, anMessage);

			// Encapsulation and serialization
			PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorEnc);
			byte[] sessionKey = encapsulationPair.getSessionKey();
			PairingCipherSerParameter header = encapsulationPair.getHeader();
			byte[] byteArrayHeader = CommonUtils.SerObject(header);
			CipherParameters anHeader = (CipherParameters) CommonUtils.deserObject(byteArrayHeader);
			Assert.assertEquals(anHeader, anHeader);
			header = (PairingCipherSerParameter) anHeader;

			// Decapsulation
			byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorEnc, header);
			Assert.assertArrayEquals(sessionKey, anSessionKey);
		} catch (InvalidCipherTextException e) {
			// correct if getting there, nothing to do.
		} catch (Exception e) {
			logger.info("Invalid delegate decryption test failed, " + "identity vector = "
					+ Arrays.toString(identityVector) + ", " + "delegate ident. = " + delegateId + ", "
					+ "iv encapsulation = " + Arrays.toString(identityVectorEnc));
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void runAllTests(PairingParameters pairingParameters) {
		Pairing pairing = PairingFactory.getPairing(pairingParameters);
		try {
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters, identityVector123.length);
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
			try_valid_decryption(pairing, publicKey, masterKey, identityVector1, identityVector12);
			try_valid_decryption(pairing, publicKey, masterKey, identityVector1, identityVector123);
			try_valid_decryption(pairing, publicKey, masterKey, identityVector12, identityVector123);
			try_valid_decryption(pairing, publicKey, masterKey, identityVector123, identityVector123);
			try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector1, "ID_2", identityVector12);
			try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector1, "ID_2", identityVector123);
			try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector12, "ID_3", identityVector123);

			// test valid example
			logger.info("Test invalid examples");
			try_invalid_decryption(pairing, publicKey, masterKey, identityVector3, identityVector1);
			try_invalid_decryption(pairing, publicKey, masterKey, identityVector31, identityVector1);
			try_invalid_decryption(pairing, publicKey, masterKey, identityVector31, identityVector123);
			try_invalid_decryption(pairing, publicKey, masterKey, identityVector132, identityVector123);
			try_delegation_invalid_decryption(pairing, publicKey, masterKey, identityVector3, "ID_1", identityVector1);
			try_delegation_invalid_decryption(pairing, publicKey, masterKey, identityVector12, "ID_3",
					identityVector132);
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

	public void testHIBEBB04Engine() {
		this.engine = HIBEBB04Engine.getInstance();
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}

	public void testHIBEBBG05Engine() {
		this.engine = HIBEBBG05Engine.getInstance();
		runAllTests(PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
	}
}
