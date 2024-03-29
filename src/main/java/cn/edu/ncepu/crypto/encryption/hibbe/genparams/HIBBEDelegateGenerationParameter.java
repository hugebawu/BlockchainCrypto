package cn.edu.ncepu.crypto.encryption.hibbe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE secret key delegation parameter.
 */
public class HIBBEDelegateGenerationParameter extends PairingKeyDelegationParameter {
	private final int index;
	private final String delegateId;

	public HIBBEDelegateGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter secretKeyParameter, int index, String id) {
		super(publicKeyParameter, secretKeyParameter);
		this.index = index;
		this.delegateId = id;
	}

	public int getIndex() {
		return this.index;
	}

	public String getDelegateId() {
		return this.delegateId;
	}
}
