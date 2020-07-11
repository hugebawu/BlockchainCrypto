package cn.edu.ncepu.crypto.encryption.ibe.lw10;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.IBEEngine;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.generators.IBELW10DecryptionGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.generators.IBELW10EncryptionGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.generators.IBELW10KeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.generators.IBELW10SecretKeyGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.serparams.IBELW10CiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.serparams.IBELW10HeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.serparams.IBELW10MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.serparams.IBELW10SecretKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE engine.
 */
public class IBELW10Engine extends IBEEngine {
	// Scheme name, used for exceptions
	private static final String SCHEME_NAME = "Lewko-Waters-10 IBE scheme";

	private static IBELW10Engine engine;

	public static IBELW10Engine getInstance() {
		if (engine == null) {
			engine = new IBELW10Engine();
		}
		return engine;
	}

	private IBELW10Engine() {
		super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
	}

	public PairingKeySerPair setup(PairingParameters pairingParameters) {
		IBELW10KeyPairGenerator keyPairGenerator = new IBELW10KeyPairGenerator();
		keyPairGenerator.init(new IBEKeyPairGenerationParameter(pairingParameters));

		return keyPairGenerator.generateKeyPair();
	}

	public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String id) {
		if (!(publicKey instanceof IBELW10PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBELW10PublicKeySerParameter.class.getName());
		}
		if (!(masterKey instanceof IBELW10MasterSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey,
					IBELW10MasterSecretKeySerParameter.class.getName());
		}
		IBELW10SecretKeyGenerator secretKeyGenerator = new IBELW10SecretKeyGenerator();
		secretKeyGenerator.init(new IBESecretKeyGenerationParameter(publicKey, masterKey, id));

		return secretKeyGenerator.generateKey();
	}

	public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id) {
		if (!(publicKey instanceof IBELW10PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBELW10PublicKeySerParameter.class.getName());
		}
		IBELW10EncryptionGenerator encryptionGenerator = new IBELW10EncryptionGenerator();
		encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, null));

		return encryptionGenerator.generateEncryptionPair();
	}

	public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String id, Element message) {
		if (!(publicKey instanceof IBELW10PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBELW10PublicKeySerParameter.class.getName());
		}
		IBELW10EncryptionGenerator encryptionGenerator = new IBELW10EncryptionGenerator();
		encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, message));

		return encryptionGenerator.generateCiphertext();
	}

	public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id,
			PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
		if (!(publicKey instanceof IBELW10PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBELW10PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof IBELW10SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					IBELW10SecretKeySerParameter.class.getName());
		}
		if (!(ciphertext instanceof IBELW10CiphertextSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,
					IBELW10CiphertextSerParameter.class.getName());
		}
		IBELW10DecryptionGenerator decryptionGenerator = new IBELW10DecryptionGenerator();
		decryptionGenerator.init(new IBEDecryptionGenerationParameter(publicKey, secretKey, id, ciphertext));
		return decryptionGenerator.recoverMessage();
	}

	public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id,
			PairingCipherSerParameter header) throws InvalidCipherTextException {
		if (!(publicKey instanceof IBELW10PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBELW10PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof IBELW10SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					IBELW10SecretKeySerParameter.class.getName());
		}
		if (!(header instanceof IBELW10HeaderSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header,
					IBELW10HeaderSerParameter.class.getName());
		}
		IBELW10DecryptionGenerator decryptionGenerator = new IBELW10DecryptionGenerator();
		decryptionGenerator.init(new IBEDecryptionGenerationParameter(publicKey, secretKey, id, header));
		return decryptionGenerator.recoverKey();
	}

	public String getEngineName() {
		return SCHEME_NAME;
	}
}
