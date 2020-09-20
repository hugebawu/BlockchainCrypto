package cn.edu.ncepu.crypto.encryption.re.genparams;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * RE intermediate ciphertext generation parameter.
 */
public class REIntermediateGenerationParameter extends PairingEncapsulationGenerationParameter {
	private final int n;
	private ChameleonHasher chameleonHasher;
	private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
	private KeyGenerationParameters chameleonHashKeyGenerationParameter;

	public REIntermediateGenerationParameter(PairingKeySerParameter publicKeyParameter, int n) {
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
