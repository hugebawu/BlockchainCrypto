package cn.edu.ncepu.crypto.encryption.hibbe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE secret key generation parameter.
 */
public class HIBBESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
	private String[] ids;

	public HIBBESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter masterSecretKeyParameter, String[] ids) {
		super(publicKeyParameter, masterSecretKeyParameter);
		this.ids = ids;
	}

	public String getIdAt(int index) {
		return ids[index];
	}

	public String[] getIds() {
		return this.ids;
	}
}
