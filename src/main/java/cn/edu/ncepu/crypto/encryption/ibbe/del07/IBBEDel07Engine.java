package cn.edu.ncepu.crypto.encryption.ibbe.del07;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.generators.IBBEDel07DecapsulationGenerator;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.generators.IBBEDel07EncapsulationPairGenerator;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.generators.IBBEDel07KeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.generators.IBBEDel07SecretKeyGenerator;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.serparams.IBBEDel07HeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.serparams.IBBEDel07MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.serparams.IBBEDel07SecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.genparams.IBBEDecapsulationGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.genparams.IBBEEncapsulationGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.genparams.IBBEKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.genparams.IBBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Engine for Delerablée IBBE scheme.
 */
public class IBBEDel07Engine extends IBBEEngine {
	// Scheme name, used for exceptions
	public static final String SCHEME_NAME = "Delerablée-07 IBBE";

	private static IBBEDel07Engine engine;

	public static IBBEDel07Engine getInstance() {
		if (engine == null) {
			engine = new IBBEDel07Engine();
		}
		return engine;
	}

	private IBBEDel07Engine() {
		super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
	}

	@Override
	public PairingKeySerPair setup(PairingParameters pairingParameters, int maxBroadcastReceiver) {
		IBBEDel07KeyPairGenerator keyPairGenerator = new IBBEDel07KeyPairGenerator();
		keyPairGenerator.init(new IBBEKeyPairGenerationParameter(pairingParameters, maxBroadcastReceiver));

		return keyPairGenerator.generateKeyPair();
	}

	@Override
	public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String id) {
		if (!(publicKey instanceof IBBEDel07PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBBEDel07PublicKeySerParameter.class.getName());
		}
		if (!(masterKey instanceof IBBEDel07MasterSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey,
					IBBEDel07MasterSecretKeySerParameter.class.getName());
		}
		IBBEDel07SecretKeyGenerator secretKeyGenerator = new IBBEDel07SecretKeyGenerator();
		secretKeyGenerator.init(new IBBESecretKeyGenerationParameter(publicKey, masterKey, id));

		return secretKeyGenerator.generateKey();
	}

	@Override
	public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
		if (!(publicKey instanceof IBBEDel07PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBBEDel07PublicKeySerParameter.class.getName());
		}
		IBBEDel07EncapsulationPairGenerator keyEncapsulationPairGenerator = new IBBEDel07EncapsulationPairGenerator();
		keyEncapsulationPairGenerator.init(new IBBEEncapsulationGenerationParameter(publicKey, ids));

		return keyEncapsulationPairGenerator.generateEncryptionPair();
	}

	@Override
	public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids,
			PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
		if (!(publicKey instanceof IBBEDel07PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,
					IBBEDel07PublicKeySerParameter.class.getName());
		}
		if (!(secretKey instanceof IBBEDel07SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey,
					IBBEDel07SecretKeySerParameter.class.getName());
		}
		if (!(ciphertext instanceof IBBEDel07HeaderSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,
					IBBEDel07HeaderSerParameter.class.getName());
		}
		IBBEDel07DecapsulationGenerator keyDecapsulationGenerator = new IBBEDel07DecapsulationGenerator();
		keyDecapsulationGenerator.init(new IBBEDecapsulationGenerationParameter(publicKey, secretKey, ids, ciphertext));
		return keyDecapsulationGenerator.recoverKey();
	}

	public String getEngineName() {
		return SCHEME_NAME;
	}

}
