package cn.edu.ncepu.crypto.encryption.abe.kpabe.genparams;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * KP-ABE intermediate ciphertext generation parameter.
 */
public class KPABEIntermediateGenerationParameter extends PairingEncapsulationGenerationParameter {
	private final int n;
	private ChameleonHasher chameleonHasher;
	private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
	private KeyGenerationParameters chameleonHashKeyGenerationParameter;

	public KPABEIntermediateGenerationParameter(PairingKeySerParameter publicKeyParameter, int n) {
		super(publicKeyParameter);
		this.n = n;
	}

	public void setChameleonHasher(ChameleonHasher chameleonHasher) {
		this.chameleonHasher = chameleonHasher;
	}

	public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator keyPairGenerator) {
		this.chameleonHashKeyPairGenerator = keyPairGenerator;
	}

	public void setChameleonHashKeyGenerationParameter(KeyGenerationParameters keyGenerationParameter) {
		this.chameleonHashKeyGenerationParameter = keyGenerationParameter;
	}

	public ChameleonHasher getChameleonHasher() {
		return this.chameleonHasher;
	}

	public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
		return this.chameleonHashKeyPairGenerator;
	}

	public KeyGenerationParameters getChameleonHashKeyGenerationParameter() {
		return this.chameleonHashKeyGenerationParameter;
	}

	public int getN() {
		return this.n;
	}
}
