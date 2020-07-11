package cn.edu.ncepu.crypto.encryption.re.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption secret key generation parameter.
 */
public class RESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
	private String id;

	public RESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter masterSecretKeyParameter, String id) {
		super(publicKeyParameter, masterSecretKeyParameter);
		this.id = id;
	}

	public String getId() {
		return this.id;
	}
}
