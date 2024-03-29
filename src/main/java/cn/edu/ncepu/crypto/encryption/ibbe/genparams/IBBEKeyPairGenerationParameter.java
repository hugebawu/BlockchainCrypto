package cn.edu.ncepu.crypto.encryption.ibbe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE public key / master secret key generation parameter.
 */
public class IBBEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
	private final int maxBroadcastReceiver;

	public IBBEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxBroadcastReceiver) {
		super(pairingParameters);

		this.maxBroadcastReceiver = maxBroadcastReceiver;
	}

	public int getMaxBroadcastReceiver() {
		return this.maxBroadcastReceiver;
	}
}
