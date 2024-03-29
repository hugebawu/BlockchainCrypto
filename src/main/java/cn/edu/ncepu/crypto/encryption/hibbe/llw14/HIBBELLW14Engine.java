package cn.edu.ncepu.crypto.encryption.hibbe.llw14;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.ncepu.crypto.encryption.hibbe.genparams.HIBBEDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.genparams.HIBBEDelegateGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.genparams.HIBBEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.genparams.HIBBEKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.genparams.HIBBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.generators.HIBBELLW14DecryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.generators.HIBBELLW14EncryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.generators.HIBBELLW14KeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.generators.HIBBELLW14SecretKeyGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14CiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14HeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14SecretKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu HIBBE engine published in 2014.
 */
public class HIBBELLW14Engine extends HIBBEEngine {
	// Scheme name, used for exceptions
	public static final String SCHEME_NAME = "Liu-Liu-Wu-14 CPA-secure composite-order HIBBE";

	private static HIBBELLW14Engine engine;

	public static HIBBELLW14Engine getInstance() {
		if (engine == null) {
			engine = new HIBBELLW14Engine();
		}
		return engine;
	}

	private HIBBELLW14Engine() {
		super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
	}

	public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
		HIBBELLW14KeyPairGenerator keyPairGenerator = new HIBBELLW14KeyPairGenerator();
		keyPairGenerator.init(new HIBBEKeyPairGenerationParameter(pairingParameters, maxUser));

		return keyPairGenerator.generateKeyPair();
	}

	public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String[] ids) {
		if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW14PublicKeySerParameter.class.getName());
		}
		if (!(masterKey instanceof HIBBELLW14MasterSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey,
					HIBBELLW14MasterSecretKeySerParameter.class.getName());
		}
		HIBBELLW14SecretKeyGenerator secretKeyGenerator = new HIBBELLW14SecretKeyGenerator();
		secretKeyGenerator.init(new HIBBESecretKeyGenerationParameter(publicKey, masterKey, ids));

		return secretKeyGenerator.generateKey();
	}

	public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
			int index, String id) {
		if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW14PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBBELLW14SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBBELLW14SecretKeySerParameter.class.getName());
		}
		HIBBELLW14SecretKeyGenerator secretKeyGenerator = new HIBBELLW14SecretKeyGenerator();
		secretKeyGenerator.init(new HIBBEDelegateGenerationParameter(publicKey, secretKey, index, id));

		return secretKeyGenerator.generateKey();
	}

	public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message) {
		if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW14PublicKeySerParameter.class.getName());
		}
		HIBBELLW14EncryptionGenerator encryptionGenerator = new HIBBELLW14EncryptionGenerator();
		encryptionGenerator.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, message));

		return encryptionGenerator.generateCiphertext();
	}

	public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
		if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW14PublicKeySerParameter.class.getName());
		}
		HIBBELLW14EncryptionGenerator encryptionGenerator = new HIBBELLW14EncryptionGenerator();
		encryptionGenerator.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, null));

		return encryptionGenerator.generateEncryptionPair();
	}

	public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids,
			PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
		if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW14PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBBELLW14SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBBELLW14SecretKeySerParameter.class.getName());
		}
		if (!(ciphertext instanceof HIBBELLW14CiphertextSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,
					HIBBELLW14CiphertextSerParameter.class.getName());
		}
		HIBBELLW14DecryptionGenerator decryptionGenerator = new HIBBELLW14DecryptionGenerator();
		decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext));
		return decryptionGenerator.recoverMessage();
	}

	public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids,
			PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
		if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW14PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBBELLW14SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBBELLW14SecretKeySerParameter.class.getName());
		}
		if (!(ciphertext instanceof HIBBELLW14HeaderSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,
					HIBBELLW14HeaderSerParameter.class.getName());
		}
		HIBBELLW14DecryptionGenerator decryptionGenerator = new HIBBELLW14DecryptionGenerator();
		decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext));
		return decryptionGenerator.recoverKey();
	}
}
