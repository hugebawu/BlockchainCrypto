package com.example.signature.pks;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.signature.pks.PairingDigestSigner;
import cn.edu.ncepu.crypto.signature.pks.bb04.BB04SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bb04.BB04SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bb04.BB04Signer;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08Signer;
import cn.edu.ncepu.crypto.signature.pks.bls01.BLS01SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bls01.BLS01SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bls01.BLS01Signer;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Public key signature test.
 */
public class PKSSignerTest {
	private static final Logger logger = LoggerFactory.getLogger(PKSSignerTest.class);
	private PairingKeyPairGenerator asymmetricKeySerPairGenerator;
	private Signer signer;

	private void processTest() {
		// KeyGen
		PairingKeySerPair keyPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
		PairingKeySerParameter publicKey = keyPair.getPublic();
		PairingKeySerParameter secretKey = keyPair.getPrivate();

		logger.info("========================================");
		logger.info("Test signer functionality");
		try {
			// signature
			byte[] message = "Message".getBytes(StandardCharsets.UTF_8);
			signer.init(true, secretKey);
			signer.update(message, 0, message.length);
			byte[] signature = signer.generateSignature();
			logger.info("Signature length = " + signature.length + " byte");

			byte[] messagePrime = "MessagePrime".getBytes(StandardCharsets.UTF_8);
			signer.init(true, secretKey);
			signer.update(messagePrime, 0, messagePrime.length);
			byte[] signaturePrime = signer.generateSignature();
			logger.info("Signature' length = " + signaturePrime.length + " byte");

			// verify
			signer.init(false, publicKey);
			signer.update(message, 0, message.length);
			if (!signer.verifySignature(signature)) {
				logger.info("cannot verify valid signature, test abort...");
				System.exit(0);
			}

			signer.init(false, publicKey);
			signer.update(message, 0, message.length);
			if (signer.verifySignature(signaturePrime)) {
				logger.info("Verify passed for invalid signature, test abort...");
				System.exit(0);
			}
		} catch (CryptoException e) {
			e.printStackTrace();
		}
        logger.info("Pairing signer functionality test pass.");

		logger.info("========================================");
		logger.info("Test signer parameters serialization & de-serialization.");
		try {
			// serialize public key
			logger.info("Test serialize & de-serialize public key.");
			byte[] byteArrayPublicKey = PairingUtils.SerCipherParameter(publicKey);
			CipherParameters anPublicKey = PairingUtils.deserCipherParameters(byteArrayPublicKey);
			assertEquals(publicKey, anPublicKey);

			// serialize secret key
			logger.info("Test serialize & de-serialize secret keys.");
			// serialize sk4
			byte[] byteArraySecretKey = PairingUtils.SerCipherParameter(secretKey);
			CipherParameters anSecretKey = PairingUtils.deserCipherParameters(byteArraySecretKey);
			assertEquals(secretKey, anSecretKey);

			logger.info("Signer parameter serialization tests passed.");
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	@Ignore
	@Test
	public void testBLS01Signer() {
		PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_f_256);
		logger.info("Test Boneh-Lynn-Shacham 2001 signature.");
		this.asymmetricKeySerPairGenerator = new BLS01SignKeyPairGenerator();
		this.asymmetricKeySerPairGenerator.init(new BLS01SignKeyPairGenerationParameter(pairingParameters));
		this.signer = new PairingDigestSigner(new BLS01Signer(), new SHA256Digest());
		this.processTest();
	}

	@Ignore
	@Test
	public void testBB04Signer() {
		PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
		logger.info("Test Boneh-Boyen 2004 signature.");
		this.asymmetricKeySerPairGenerator = new BB04SignKeyPairGenerator();
		this.asymmetricKeySerPairGenerator.init(new BB04SignKeyPairGenerationParameter(pairingParameters));
		this.signer = new PairingDigestSigner(new BB04Signer(), new SHA256Digest());
		this.processTest();
	}

	@Ignore
	@Test
	public void testBB08Signer() {
		PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
		logger.info("Test Boneh-Boyen 2008 signature.");
		this.asymmetricKeySerPairGenerator = new BB08SignKeyPairGenerator();
		this.asymmetricKeySerPairGenerator.init(new BB08SignKeyPairGenerationParameter(pairingParameters));
		this.signer = new PairingDigestSigner(new BB08Signer(), new SHA256Digest());
		this.processTest();
	}

}
