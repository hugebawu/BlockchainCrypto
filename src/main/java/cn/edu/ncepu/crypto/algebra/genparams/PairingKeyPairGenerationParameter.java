package cn.edu.ncepu.crypto.algebra.genparams;

import org.bouncycastle.crypto.KeyGenerationParameters;

import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing public key / master secret key generation parameter.
 */
public class PairingKeyPairGenerationParameter extends KeyGenerationParameters {
	private final PairingParameters pairingParameters;

	public PairingKeyPairGenerationParameter(PairingParameters pairingParameters) {
		super(null, PairingParametersGenerationParameter.STENGTH);
		this.pairingParameters = pairingParameters;
	}

	public PairingParameters getPairingParameters() {
		return this.pairingParameters;
	}
}