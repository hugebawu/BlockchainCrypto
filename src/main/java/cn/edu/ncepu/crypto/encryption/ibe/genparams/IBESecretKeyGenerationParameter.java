package cn.edu.ncepu.crypto.encryption.ibe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Identity-Based Encryption secret key generation parameter.
 */
public class IBESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
	// user id used for generating the user secret key
	private final String id;

	public IBESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter masterSecretKeyParameter, String id) {
		super(publicKeyParameter, masterSecretKeyParameter);
		this.id = id;
	}

	public String getId() {
		return this.id;
	}

}