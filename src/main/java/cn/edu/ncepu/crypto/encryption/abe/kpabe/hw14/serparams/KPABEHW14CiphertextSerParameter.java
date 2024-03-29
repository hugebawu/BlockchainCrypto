package cn.edu.ncepu.crypto.encryption.abe.kpabe.hw14.serparams;

import java.util.Arrays;
import java.util.Map;

import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE ciphertext parameter.
 */
public class KPABEHW14CiphertextSerParameter extends KPABEHW14HeaderSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1571020004395350722L;
	private transient Element C;
	private final byte[] byteArrayC;

	public KPABEHW14CiphertextSerParameter(PairingParameters pairingParameters, Element C, Element C0,
			Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s) {
		super(pairingParameters, C0, C1s, C2s, C3s);
		this.C = C.getImmutable();
		this.byteArrayC = this.C.toBytes();
	}

	public Element getC() {
		return this.C.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof KPABEHW14CiphertextSerParameter) {
			KPABEHW14CiphertextSerParameter that = (KPABEHW14CiphertextSerParameter) anObject;
			return PairingUtils.isEqualElement(this.C, that.C) && Arrays.equals(this.byteArrayC, that.byteArrayC)
					&& super.equals(anObject);
		}
		return false;
	}

	private void readObject(java.io.ObjectInputStream objectInputStream)
			throws java.io.IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.C = pairing.getGT().newElementFromBytes(this.byteArrayC);
	}
}
