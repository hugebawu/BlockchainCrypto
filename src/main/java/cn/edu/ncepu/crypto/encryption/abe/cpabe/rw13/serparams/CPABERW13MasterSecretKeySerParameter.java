package cn.edu.ncepu.crypto.encryption.abe.cpabe.rw13.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE master secret key parameter.
 */
public class CPABERW13MasterSecretKeySerParameter extends PairingKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7860686051652712063L;
	private transient Element alpha;
	private final byte[] byteArrayAlpha;

	public CPABERW13MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
		super(true, pairingParameters);
		this.alpha = alpha.getImmutable();
		this.byteArrayAlpha = this.alpha.toBytes();
	}

	public Element getAlpha() {
		return this.alpha.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof CPABERW13MasterSecretKeySerParameter) {
			CPABERW13MasterSecretKeySerParameter that = (CPABERW13MasterSecretKeySerParameter) anObject;
			// compare alpha
			if (!(PairingUtils.isEqualElement(this.alpha, that.alpha))) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayAlpha, that.byteArrayAlpha)) {
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
		this.alpha = pairing.getZr().newElementFromBytes(this.byteArrayAlpha).getImmutable();
	}
}
