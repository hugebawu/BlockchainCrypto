package cn.edu.ncepu.crypto.encryption.hibe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * HIBE decryption generation parameter.
 */
public class HIBEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
	private final String[] ids;

	public HIBEDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter secretKeyParameter, String[] ids, PairingCipherSerParameter ciphertextParameter) {
		super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
		this.ids = ids;
	}

	public int getLength() {
		return this.ids.length;
	}

	public String[] getIds() {
		return this.ids;
	}

	public String getIdsAt(int index) {
		return this.ids[index];
	}
}
