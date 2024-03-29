package cn.edu.ncepu.crypto.algebra.genparams;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing secret key delegation parameter.
 */
public class PairingKeyDelegationParameter extends KeyGenerationParameters {
	private final PairingKeySerParameter publicKeyParameter;
	private final PairingKeySerParameter secretKeyParameter;

	public PairingKeyDelegationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter secretKeyParameter) {
		super(null, PairingParametersGenerationParameter.STENGTH);
		this.publicKeyParameter = publicKeyParameter;
		this.secretKeyParameter = secretKeyParameter;
	}

	public PairingKeySerParameter getPublicKeyParameter() {
		return this.publicKeyParameter;
	}

	public PairingKeySerParameter getSecretKeyParameter() {
		return this.secretKeyParameter;
	}
}