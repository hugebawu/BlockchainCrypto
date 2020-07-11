package cn.edu.ncepu.crypto.encryption.hibbe.llw16b;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
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
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bDecryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bEncryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bKeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bSecretKeyGenerator;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bCiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bHeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bSecretKeySerParameter;
import cn.edu.ncepu.crypto.signature.pks.PairingDigestSigner;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08Signer;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE engine.
 */
public class HIBBELLW16bEngine extends HIBBEEngine {
	// Scheme name, used for exceptions
	public static final String SCHEME_NAME = "Liu-Liu-Wu-16 CCA2-secure prime-order HIBBE";

	private static HIBBELLW16bEngine engine;
	private Signer signer = new PairingDigestSigner(new BB08Signer(), new SHA256Digest());
	private PairingKeyPairGenerator signKeyPairGenerator = new BB08SignKeyPairGenerator();
	private KeyGenerationParameters signKeyPairGenerationParameter = new BB08SignKeyPairGenerationParameter(
			PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512));

	public String getEngineName() {
		return SCHEME_NAME;
	}

	public static HIBBELLW16bEngine getInstance() {
		if (engine == null) {
			engine = new HIBBELLW16bEngine();
		}
		return engine;
	}

	private HIBBELLW16bEngine() {
		super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CCA2, PredicateSecLevel.NON_ANON);
		this.signKeyPairGenerator.init(signKeyPairGenerationParameter);
	}

	public void setSigner(Signer signer, PairingKeyPairGenerator signKeyPairGenerator,
			KeyGenerationParameters signKeyPairGenerationParameter) {
		this.signer = signer;
		this.signKeyPairGenerator = signKeyPairGenerator;
		this.signKeyPairGenerationParameter = signKeyPairGenerationParameter;
		this.signKeyPairGenerator.init(signKeyPairGenerationParameter);
	}

	public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
		HIBBELLW16bKeyPairGenerator keyPairGenerator = new HIBBELLW16bKeyPairGenerator();
		keyPairGenerator.init(new HIBBEKeyPairGenerationParameter(pairingParameters, maxUser, signer));

		return keyPairGenerator.generateKeyPair();
	}

	public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String[] ids) {
		if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW16bPublicKeySerParameter.class.getName());
		}
		if (!(masterKey instanceof HIBBELLW16bMasterSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey,
					HIBBELLW16bMasterSecretKeySerParameter.class.getName());
		}
		HIBBELLW16bSecretKeyGenerator secretKeyGenerator = new HIBBELLW16bSecretKeyGenerator();
		secretKeyGenerator.init(new HIBBESecretKeyGenerationParameter(publicKey, masterKey, ids));

		return secretKeyGenerator.generateKey();
	}

	public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
			int index, String id) {
		if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW16bPublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBBELLW16bSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBBELLW16bSecretKeySerParameter.class.getName());
		}
		HIBBELLW16bSecretKeyGenerator secretKeyGenerator = new HIBBELLW16bSecretKeyGenerator();
		secretKeyGenerator.init(new HIBBEDelegateGenerationParameter(publicKey, secretKey, index, id));

		return secretKeyGenerator.generateKey();
	}

	public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message) {
		if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW16bPublicKeySerParameter.class.getName());
		}
		HIBBELLW16bEncryptionGenerator encryptionGenerator = new HIBBELLW16bEncryptionGenerator();
		encryptionGenerator
				.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, message, signer, signKeyPairGenerator));
		return encryptionGenerator.generateCiphertext();
	}

	public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
		if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW16bPublicKeySerParameter.class.getName());
		}
		HIBBELLW16bEncryptionGenerator encryptionGenerator = new HIBBELLW16bEncryptionGenerator();
		encryptionGenerator
				.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, null, signer, signKeyPairGenerator));
		return encryptionGenerator.generateEncryptionPair();
	}

	public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids,
			PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
		if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW16bPublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBBELLW16bSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBBELLW16bSecretKeySerParameter.class.getName());
		}
		if (!(ciphertext instanceof HIBBELLW16bCiphertextSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,
					HIBBELLW16bCiphertextSerParameter.class.getName());
		}
		HIBBELLW16bDecryptionGenerator decryptionGenerator = new HIBBELLW16bDecryptionGenerator();
		decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext, signer));

		return decryptionGenerator.recoverMessage();
	}

	public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids,
			PairingCipherSerParameter header) throws InvalidCipherTextException {
		if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					HIBBELLW16bPublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof HIBBELLW16bSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					HIBBELLW16bSecretKeySerParameter.class.getName());
		}
		if (!(header instanceof HIBBELLW16bHeaderSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header,
					HIBBELLW16bHeaderSerParameter.class.getName());
		}
		HIBBELLW16bDecryptionGenerator decryptionGenerator = new HIBBELLW16bDecryptionGenerator();
		decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(publicKey, secretKey, ids, header, signer));

		return decryptionGenerator.recoverKey();
	}
}
