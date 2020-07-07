package cn.edu.ncepu.crypto.algebra.genparams;

import java.math.BigInteger;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing encryption generation parameter.
 */
public abstract class PairingEncryptionGenerationParameter extends PairingEncapsulationGenerationParameter {
	// parameter for encryption.
	private Element message;
	private BigInteger biMessage;

	public PairingEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, Element message) {
		super(publicKeyParameter);
		if (message != null) {
			this.message = message.getImmutable();
		}
	}

	public PairingEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, BigInteger biMessage) {
		super(publicKeyParameter);
		setBImessage(biMessage);
	}

	public Element getMessage() {
		if (message == null) {
			return null;
		}
		return this.message.duplicate();
	}

	public BigInteger getBImessage() {
		return biMessage;
	}

	public void setBImessage(BigInteger bImessage) {
		this.biMessage = bImessage;
	}
}
