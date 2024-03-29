package cn.edu.ncepu.crypto.encryption.hibe.bbg05;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.HIBEEngine;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.generators.HIBEBBG05DecryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.generators.HIBEBBG05EncryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05CiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05HeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEDelegateGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE engine.
 */
public class HIBEBBG05Engine extends HIBEEngine {
	// Scheme name, used for exceptions
	public static final String SCHEME_NAME = "Boneh-Boyen-Goh-05 HIBE scheme";

	private static HIBEBBG05Engine engine;

	public static HIBEBBG05Engine getInstance() {
		if (engine == null) {
			engine = new HIBEBBG05Engine();
		}
		return engine;
	}

	private HIBEBBG05Engine() {
		super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
	}

	public PairingKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
		HIBEBBG05KeyPairGenerator keyPairGenerator = new HIBEBBG05KeyPairGenerator();
		keyPairGenerator.init(new HIBEKeyPairGenerationParameter(pairingParameters, maxDepth));

		return keyPairGenerator.generateKeyPair();
	}

	public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String... ids) {
		if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBEBBG05PublicKeySerParameter.class.getName());
		}
		if (!(masterKey instanceof HIBEBBG05MasterSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey,
					HIBEBBG05MasterSecretKeySerParameter.class.getName());
		}
		HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
		secretKeyGenerator.init(new HIBESecretKeyGenerationParameter(publicKey, masterKey, ids));

		return secretKeyGenerator.generateKey();
	}

	public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
			String id) {
		if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBEBBG05PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBEBBG05SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBEBBG05SecretKeySerParameter.class.getName());
		}
		HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
		secretKeyGenerator.init(new HIBEDelegateGenerationParameter(publicKey, secretKey, id));

		return secretKeyGenerator.generateKey();
	}

	public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message) {
		if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBEBBG05PublicKeySerParameter.class.getName());
		}
		HIBEBBG05EncryptionGenerator encryptionGenerator = new HIBEBBG05EncryptionGenerator();
		encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, message));

		return encryptionGenerator.generateCiphertext();
	}

	public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
		if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBEBBG05PublicKeySerParameter.class.getName());
		}
		HIBEBBG05EncryptionGenerator encryptionGenerator = new HIBEBBG05EncryptionGenerator();
		encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, null));

		return encryptionGenerator.generateEncryptionPair();
	}

	public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids,
			PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
		if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBEBBG05PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBEBBG05SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBEBBG05SecretKeySerParameter.class.getName());
		}
		if (!(ciphertext instanceof HIBEBBG05CiphertextSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,
					HIBEBBG05CiphertextSerParameter.class.getName());
		}
		HIBEBBG05DecryptionGenerator decapsulationGenerator = new HIBEBBG05DecryptionGenerator();
		decapsulationGenerator.init(new HIBEDecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext));
		return decapsulationGenerator.recoverMessage();
	}

	public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids,
			PairingCipherSerParameter header) throws InvalidCipherTextException {
		if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBEBBG05PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBEBBG05SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBEBBG05SecretKeySerParameter.class.getName());
		}
		if (!(header instanceof HIBEBBG05HeaderSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header,
					HIBEBBG05HeaderSerParameter.class.getName());
		}
		HIBEBBG05DecryptionGenerator decapsulationGenerator = new HIBEBBG05DecryptionGenerator();
		decapsulationGenerator.init(new HIBEDecryptionGenerationParameter(publicKey, secretKey, ids, header));
		return decapsulationGenerator.recoverKey();
	}

	public String getEngineName() {
		return SCHEME_NAME;
	}
}
