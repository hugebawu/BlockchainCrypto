package cn.edu.ncepu.crypto.encryption.hibbe.genparams;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE encryption generation parameter.
 */
public class HIBBEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
	private final String[] ids;
	private final Signer signer;
	private final PairingKeyPairGenerator signKeyPairGenerator;
	private final Digest digest;

	public HIBBEEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids,
			Element message) {
		super(publicKeyParameter, message);
		this.ids = ids;
		this.signer = null;
		this.signKeyPairGenerator = null;
		this.digest = null;
	}

	public HIBBEEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids, Element message,
			Signer signer, PairingKeyPairGenerator signKeyPairGenerator) {
		super(publicKeyParameter, message);
		this.ids = ids;
		this.signer = signer;
		this.signKeyPairGenerator = signKeyPairGenerator;
		this.digest = null;
	}

	public HIBBEEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids, Element message,
			Digest digest) {
		super(publicKeyParameter, message);
		this.ids = ids;
		this.signer = null;
		this.signKeyPairGenerator = null;
		this.digest = digest;
	}

	public PairingKeyPairGenerator getSignKeyPairGenerator() {
		return this.signKeyPairGenerator;
	}

	public Signer getSigner() {
		return this.signer;
	}

	public Digest getDigest() {
		return this.digest;
	}

	public String[] getIds() {
		return this.ids;
	}

	public String getIdAt(int index) {
		return ids[index];
	}
}
