package cn.edu.ncepu.crypto.encryption.be.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * BE secret key generation parameter.
 */
public class BESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
	private int index;

	public BESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter masterSecretKeyParameter, int index) {
		super(publicKeyParameter, masterSecretKeyParameter);
		this.index = index;
	}

	public int getIndex() {
		return this.index;
	}
}
