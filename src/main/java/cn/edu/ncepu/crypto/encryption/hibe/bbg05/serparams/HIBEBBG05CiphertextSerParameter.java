package cn.edu.ncepu.crypto.encryption.hibe.bbg05.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE ciphertext parameter.
 */
public class HIBEBBG05CiphertextSerParameter extends HIBEBBG05HeaderSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -6828363737477481623L;
	private transient Element A;
	private final byte[] byteArrayA;

	public HIBEBBG05CiphertextSerParameter(PairingParameters pairingParameters, Element A, Element B, Element C) {
		super(pairingParameters, B, C);

		this.A = A.getImmutable();
		this.byteArrayA = this.A.toBytes();
	}

	public Element getA() {
		return this.A.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof HIBEBBG05CiphertextSerParameter) {
			HIBEBBG05CiphertextSerParameter that = (HIBEBBG05CiphertextSerParameter) anObject;
			// Compare A
			return PairingUtils.isEqualElement(this.A, that.getA()) && Arrays.equals(this.byteArrayA, that.byteArrayA)
					&& super.equals(anObject);
		}
		return false;
	}

	private void readObject(java.io.ObjectInputStream objectInputStream)
			throws java.io.IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.A = pairing.getGT().newElementFromBytes(this.byteArrayA).getImmutable();
	}
}
