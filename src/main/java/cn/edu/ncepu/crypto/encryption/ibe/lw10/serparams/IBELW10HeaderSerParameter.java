package cn.edu.ncepu.crypto.encryption.ibe.lw10.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/11/30.
 *
 * Lewko-Waters IBE header parameter.
 */
public class IBELW10HeaderSerParameter extends PairingCipherSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1368138091628158865L;
	private transient Element C1;
	private final byte[] byteArrayC1;

	private transient Element C2;
	private final byte[] byteArrayC2;

	public IBELW10HeaderSerParameter(PairingParameters pairingParameters, Element C1, Element C2) {
		super(pairingParameters);
		this.C1 = C1.getImmutable();
		this.byteArrayC1 = this.C1.toBytes();

		this.C2 = C2.getImmutable();
		this.byteArrayC2 = this.C2.toBytes();
	}

	public Element getC1() {
		return this.C1.duplicate();
	}

	public Element getC2() {
		return this.C2.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof IBELW10HeaderSerParameter) {
			IBELW10HeaderSerParameter that = (IBELW10HeaderSerParameter) anObject;
			// Compare C1
			if (!PairingUtils.isEqualElement(this.C1, that.getC1())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayC1, that.byteArrayC1)) {
				return false;
			}
			// Compare C2
			if (!PairingUtils.isEqualElement(this.C2, that.getC2())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayC2, that.byteArrayC2)) {
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
		this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1).getImmutable();
		this.C2 = pairing.getG1().newElementFromBytes(this.byteArrayC2).getImmutable();
	}
}
