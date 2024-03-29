package cn.edu.ncepu.crypto.encryption.hibbe.llw16a.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE header parameter.
 */
public class HIBBELLW16aHeaderSerParameter extends PairingCipherSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 2149358144667853511L;
	private transient Element C0;
	private final byte[] byteArrayC0;

	private transient Element C1;
	private final byte[] byteArrayC1;

	public HIBBELLW16aHeaderSerParameter(PairingParameters pairingParameters, Element C0, Element C1) {
		super(pairingParameters);
		this.C0 = C0.getImmutable();
		this.byteArrayC0 = this.C0.toBytes();

		this.C1 = C1.getImmutable();
		this.byteArrayC1 = this.C1.toBytes();
	}

	public Element getC0() {
		return this.C0.duplicate();
	}

	public Element getC1() {
		return this.C1.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof HIBBELLW16aHeaderSerParameter) {
			HIBBELLW16aHeaderSerParameter that = (HIBBELLW16aHeaderSerParameter) anObject;
			// Compare C0
			if (!PairingUtils.isEqualElement(this.C0, that.getC0())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
				return false;
			}
			// Compare C1
			if (!PairingUtils.isEqualElement(this.C1, that.getC1())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayC1, that.byteArrayC1)) {
				return false;
			}
			// Compare Pairing Parameters
			return this.getParameters().toString().equals(that.getParameters().toString());
		}
		return false;
	}

	private void readObject(java.io.ObjectInputStream objectInputStream)
			throws java.io.IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
		this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1).getImmutable();
	}
}