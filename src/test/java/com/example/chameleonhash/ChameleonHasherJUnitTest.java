package com.example.chameleonhash;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.TestUtils;

import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.SecurePrimeSerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/10/20.
 *
 * Chameleon hash test.
 */
public class ChameleonHasherJUnitTest extends TestCase {
	private static Logger logger = LoggerFactory.getLogger(ChameleonHasherJUnitTest.class);

	private AsymmetricKeySerPairGenerator asymmetricCipherKeyPairGenerator;
	private ChameleonHasher chameleonHasher;

	private void runAllTests() {
		// KeyGen
		AsymmetricKeySerPair keyPair = asymmetricCipherKeyPairGenerator.generateKeyPair();
		AsymmetricKeySerParameter publicKey = keyPair.getPublic();
		AsymmetricKeySerParameter secretKey = keyPair.getPrivate();

		String message1 = "This is message 1";
		String message2 = "This is message 2";
		logger.info("========================================");
		logger.info("Test chameleon hash functionality.");
		try {
			logger.info("Test inequality with different messages.");
			chameleonHasher.init(false, publicKey);
			chameleonHasher.update(message1.getBytes(), 0, message1.getBytes().length);
			byte[][] cHashResult1 = chameleonHasher.computeHash();
			chameleonHasher.reset();
			chameleonHasher.update(message2.getBytes(), 0, message2.getBytes().length);
			byte[][] cHashResult2 = chameleonHasher.computeHash();

			// Test inequality with different messages
			logger.info("Hash Result 1 = " + Arrays.toString(cHashResult1[0]));
			logger.info("Hash Result 2 = " + Arrays.toString(cHashResult2[0]));
			assertEquals(false, Arrays.equals(cHashResult1[0], cHashResult2[0]));

			// Test equality without / with randomness r
			logger.info("Test equality without / with randomness r.");
			chameleonHasher.reset();
			chameleonHasher.update(message1.getBytes(), 0, message1.getBytes().length);
			byte[][] cHashResult1Prime = chameleonHasher.computeHash(cHashResult1[0], cHashResult1[1]);
			logger.info("Hash Result 1' = " + Arrays.toString(cHashResult1Prime[0]));
			assertEquals(true, Arrays.equals(cHashResult1[0], cHashResult1Prime[0]));

			// Test collision
			logger.info("Test equality with collision finding.");
			chameleonHasher.init(true, secretKey);
			chameleonHasher.update(message2.getBytes(), 0, message2.getBytes().length);
			byte[][] cHashCollision = chameleonHasher.findCollision(cHashResult1[0], cHashResult1[1]);
			logger.info("Coll. Resist. = " + Arrays.toString(cHashCollision[0]));
			assertEquals(true, Arrays.equals(cHashResult1[0], cHashCollision[0]));
			logger.info("Chameleon hash functionality test pass.");

			logger.info("========================================");
			logger.info("Test signer parameters serialization & de-serialization.");
			// serialize public key
			logger.info("Test serialize & de-serialize public key.");
			byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
			CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
			assertEquals(publicKey, anPublicKey);

			// serialize secret key
			logger.info("Test serialize & de-serialize secret keys.");
			// serialize sk4
			byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
			CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
			assertEquals(secretKey, anSecretKey);

			logger.info("Signer parameter serialization tests passed.");
			logger.info("");

		} catch (CryptoException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void testKR00UniversalChameleonHash() {
		SecureRandom secureRandom = new SecureRandom();
		// RFC 3526, 1536-bit MODP Group
		SecurePrimeSerParameter securePrimeSerParameter = SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP;
		AsymmetricKeySerPairGenerator signKeyPairGenerator = new DLogKR00bKeyPairGenerator();
		signKeyPairGenerator.init(new DLogKR00bKeyGenerationParameters(secureRandom, securePrimeSerParameter));
		this.chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
		this.asymmetricCipherKeyPairGenerator = signKeyPairGenerator;
		logger.info("Test Krawczyk-Rabin Chameleon hash function");
		runAllTests();
	}

	public void testKR00ChameleonHash() {
		SecureRandom secureRandom = new SecureRandom();
		// RFC 3526, 1536-bit MODP Group
		SecurePrimeSerParameter securePrimeSerParameter = SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP;
		AsymmetricKeySerPairGenerator signKeyPairGenerator = new DLogKR00bKeyPairGenerator();
		signKeyPairGenerator.init(new DLogKR00bKeyGenerationParameters(secureRandom, securePrimeSerParameter));
		this.chameleonHasher = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()),
				new SHA256Digest());
		this.asymmetricCipherKeyPairGenerator = signKeyPairGenerator;
		logger.info("Test Universal Collision-Resistant Krawczyk-Rabin Chameleon hash function");
		runAllTests();
	}
}
