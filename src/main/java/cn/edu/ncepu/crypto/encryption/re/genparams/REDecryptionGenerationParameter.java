package cn.edu.ncepu.crypto.encryption.re.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;
import cn.edu.ncepu.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption decryption generation parameter.
 */
public class REDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
	private final String[] ids;
	private ChameleonHasher chameleonHasher;

	public REDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter secretKeyParameter, String[] ids, PairingCipherSerParameter ciphertextParameter) {
		super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
		// remove repeated ids
		this.ids = PairingUtils.removeDuplicates(ids);
	}

	public int getLength() {
		return this.ids.length;
	}

	public String[] getIds() {
		return this.ids;
	}

	public void setChameleonHasher(ChameleonHasher chameleonHasher) {
		this.chameleonHasher = chameleonHasher;
	}

	public ChameleonHasher getChameleonHasher() {
		return this.chameleonHasher;
	}
}
