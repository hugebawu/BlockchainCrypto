package cn.edu.ncepu.crypto.encryption.abe.cpabe.genparams;

import cn.edu.ncepu.crypto.access.AccessControlEngine;
import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;

/**
 * Created by Administrator on 2016/11/20.
 *
 * CP-ABE decryption generation parameter.
 */
public class CPABEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
	private final int[][] accessPolicy;
	private final String[] rhos;
	private final AccessControlEngine accessControlEngine;
	private ChameleonHasher chameleonHasher;

	public CPABEDecryptionGenerationParameter(AccessControlEngine accessControlEngine,
			PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter, int[][] accessPolicy,
			String[] rhos, PairingCipherSerParameter ciphertextParameter) {
		super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
		this.accessControlEngine = accessControlEngine;
		this.accessPolicy = accessPolicy;
		this.rhos = rhos;
	}

	public void setChameleonHasher(ChameleonHasher chameleonHasher) {
		this.chameleonHasher = chameleonHasher;
	}

	public int[][] getAccessPolicy() {
		return this.accessPolicy;
	}

	public String[] getRhos() {
		return this.rhos;
	}

	public AccessControlEngine getAccessControlEngine() {
		return this.accessControlEngine;
	}

	public ChameleonHasher getChameleonHasher() {
		return this.chameleonHasher;
	}
}
