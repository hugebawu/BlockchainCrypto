package cn.edu.ncepu.crypto.algebra.genparams;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing secret key generation parameter.
 */
public class PairingKeyGenerationParameter extends KeyGenerationParameters {
	private final PairingKeySerParameter masterSecretKeyParameter;
	private final PairingKeySerParameter publicKeyParameter;

	public PairingKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter masterSecretKeyParameter) {
		super(null, PairingParametersGenerationParameter.STENGTH);

		this.masterSecretKeyParameter = masterSecretKeyParameter;
		this.publicKeyParameter = publicKeyParameter;
	}

	public PairingKeySerParameter getMasterSecretKeyParameter() {
		return this.masterSecretKeyParameter;
	}

	public PairingKeySerParameter getPublicKeyParameter() {
		return this.publicKeyParameter;
	}
}
