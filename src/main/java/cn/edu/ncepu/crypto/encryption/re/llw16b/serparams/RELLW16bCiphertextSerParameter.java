package cn.edu.ncepu.crypto.encryption.re.llw16b.serparams;

import java.util.Arrays;
import java.util.Map;

import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE ciphertext parameter.
 */
public class RELLW16bCiphertextSerParameter extends RELLW16bHeaderSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -5252153475511314618L;
	private transient Element C;
	private final byte[] byteArrayC;

	public RELLW16bCiphertextSerParameter(PairingParameters pairingParameters, byte[] chameleonHash, byte[] r,
			AsymmetricKeySerParameter chameleonHashPublicKey, Element C01, Element C02, Element C, Element C0,
			Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s) {
		super(pairingParameters, chameleonHash, r, chameleonHashPublicKey, C01, C02, C0, C1s, C2s, C3s);
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
		if (anObject instanceof RELLW16bCiphertextSerParameter) {
			RELLW16bCiphertextSerParameter that = (RELLW16bCiphertextSerParameter) anObject;
			return PairingUtils.isEqualElement(this.C, that.C) && Arrays.equals(this.byteArrayC, that.byteArrayC)
					&& super.equals(anObject);
		}
		return false;
	}

	private void readObject(java.io.ObjectInputStream objectInputStream)
			throws java.io.IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.C = pairing.getGT().newElementFromBytes(this.byteArrayC).getImmutable();
	}
}
