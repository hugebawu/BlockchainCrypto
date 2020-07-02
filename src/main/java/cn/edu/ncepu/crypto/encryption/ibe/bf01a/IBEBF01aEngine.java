package cn.edu.ncepu.crypto.encryption.ibe.bf01a;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.IBEEngine;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators.IBEBF01aDecryptionGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators.IBEBF01aEncryptionGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators.IBEBF01aKeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators.IBEBF01aSecretKeyGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aCiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aHeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE engine.
 */
public class IBEBF01aEngine extends IBEEngine {
	// Scheme name, used for exceptions
	private static final String SCHEME_NAME = "Boneh-Franklin CPA-secure IBE";

	private static IBEBF01aEngine engine;

	public static IBEBF01aEngine getInstance() {
		if (engine == null) {
			engine = new IBEBF01aEngine();
		}
		return engine;
	}

	private IBEBF01aEngine() {
		super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.ANON);
	}

	@Override
	public PairingKeySerPair setup(PairingParameters pairingParameters) {
		IBEBF01aKeyPairGenerator keyPairGenerator = new IBEBF01aKeyPairGenerator();
		keyPairGenerator.init(new IBEKeyPairGenerationParameter(pairingParameters));

		return keyPairGenerator.generateKeyPair();
	}

	@Override
	public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String id) {
		if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBEBF01aPublicKeySerParameter.class.getName());
		}
		if (!(masterKey instanceof IBEBF01aMasterSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey,
					IBEBF01aMasterSecretKeySerParameter.class.getName());
		}
		IBEBF01aSecretKeyGenerator secretKeyGenerator = new IBEBF01aSecretKeyGenerator();
		secretKeyGenerator.init(new IBESecretKeyGenerationParameter(publicKey, masterKey, id));

		return secretKeyGenerator.generateKey();
	}

	@Override
	public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id) {
		if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBEBF01aPublicKeySerParameter.class.getName());
		}
		IBEBF01aEncryptionGenerator encryptionGenerator = new IBEBF01aEncryptionGenerator();
		encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, null));

		return encryptionGenerator.generateEncryptionPair();
	}

	@Override
	public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String id, Element message) {
		if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBEBF01aPublicKeySerParameter.class.getName());
		}
		IBEBF01aEncryptionGenerator encryptionGenerator = new IBEBF01aEncryptionGenerator();
		encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, message));

		return encryptionGenerator.generateCiphertext();
	}

	@Override
	public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id,
			PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
		if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBEBF01aPublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof IBEBF01aSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					IBEBF01aSecretKeySerParameter.class.getName());
		}
		if (!(ciphertext instanceof IBEBF01aCiphertextSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,
					IBEBF01aCiphertextSerParameter.class.getName());
		}
		IBEBF01aDecryptionGenerator decryptionGenerator = new IBEBF01aDecryptionGenerator();
		decryptionGenerator.init(new IBEDecryptionGenerationParameter(publicKey, secretKey, id, ciphertext));
		return decryptionGenerator.recoverMessage();
	}

	@Override
	public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id,
			PairingCipherSerParameter header) throws InvalidCipherTextException {
		if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBEBF01aPublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof IBEBF01aSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					IBEBF01aSecretKeySerParameter.class.getName());
		}
		if (!(header instanceof IBEBF01aHeaderSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header,
					IBEBF01aHeaderSerParameter.class.getName());
		}
		IBEBF01aDecryptionGenerator decryptionGenerator = new IBEBF01aDecryptionGenerator();
		decryptionGenerator.init(new IBEDecryptionGenerationParameter(publicKey, secretKey, id, header));
		return decryptionGenerator.recoverKey();
	}

	public String getEngineName() {
		return SCHEME_NAME;
	}
}
