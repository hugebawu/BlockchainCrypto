package cn.edu.ncepu.crypto.algebra.genparams;

import org.bouncycastle.crypto.CipherParameters;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing decryption generation parameter
 */
public abstract class PairingDecryptionGenerationParameter implements CipherParameters {
	private final PairingKeySerParameter publicKeyParameter;
	private final PairingKeySerParameter secretKeyParameter;
	private final PairingCipherSerParameter ciphertextParameter;

	public PairingDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter secretKeyParameter, PairingCipherSerParameter ciphertextParameter) {
		this.publicKeyParameter = publicKeyParameter;
		this.secretKeyParameter = secretKeyParameter;
		this.ciphertextParameter = ciphertextParameter;
	}

	public PairingKeySerParameter getPublicKeyParameter() {
		return this.publicKeyParameter;
	}

	public PairingKeySerParameter getSecretKeyParameter() {
		return this.secretKeyParameter;
	}

	public PairingCipherSerParameter getCiphertextParameter() {
		return this.ciphertextParameter;
	}
}
