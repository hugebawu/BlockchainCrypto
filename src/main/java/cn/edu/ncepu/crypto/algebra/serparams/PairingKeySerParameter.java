package cn.edu.ncepu.crypto.algebra.serparams;

import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Serializable asymmetric key parameter.
 * This is the same as AsymmetricKeyParameters, except that this is serializable.
 * All the asymmetric key parameters should extend this class for supporting serialization.
 */
public class PairingKeySerParameter extends PairingCipherSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -4321962451916033143L;
	private final boolean privateKey;

	public PairingKeySerParameter(boolean privateKey, PairingParameters pairingParameters) {
		super(pairingParameters);
		this.privateKey = privateKey;
	}

	public boolean isPrivate() {
		return privateKey;
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof PairingKeySerParameter) {
			PairingKeySerParameter that = (PairingKeySerParameter) anObject;
			// Compare Pairing Parameters
			return (this.privateKey == that.privateKey);
		}
		return false;
	}
}
