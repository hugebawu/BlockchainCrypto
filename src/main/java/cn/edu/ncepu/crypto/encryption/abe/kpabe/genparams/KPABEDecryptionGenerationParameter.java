package cn.edu.ncepu.crypto.encryption.abe.kpabe.genparams;

import cn.edu.ncepu.crypto.access.AccessControlEngine;
import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;
import cn.edu.ncepu.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE decryption generation parameter.
 */
public class KPABEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
	private String[] attributes;
	private AccessControlEngine accessControlEngine;
	private ChameleonHasher chameleonHasher;

	public KPABEDecryptionGenerationParameter(AccessControlEngine accessControlEngine,
			PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter, String[] attributes,
			PairingCipherSerParameter ciphertextParameter) {
		super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
		this.accessControlEngine = accessControlEngine;
		this.attributes = PairingUtils.removeDuplicates(attributes);
	}

	public void setChameleonHasher(ChameleonHasher chameleonHasher) {
		this.chameleonHasher = chameleonHasher;
	}

	public String[] getAttributes() {
		return this.attributes;
	}

	public AccessControlEngine getAccessControlEngine() {
		return this.accessControlEngine;
	}

	public ChameleonHasher getChameleonHasher() {
		return this.chameleonHasher;
	}
}
