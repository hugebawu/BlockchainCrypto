package cn.edu.ncepu.crypto.signature.pks.bls01;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham signature secret key parameters.
 */
class BLS01SignSecretPairingKeySerParameter extends PairingKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -743976565201517469L;
	private transient Element x;
	private final byte[] byteArrayX;

	BLS01SignSecretPairingKeySerParameter(PairingParameters parameters, Element x) {
		super(true, parameters);
		this.x = x.getImmutable();
		this.byteArrayX = this.x.toBytes();
	}

	public Element getX() {
		return this.x.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof BLS01SignSecretPairingKeySerParameter) {
			BLS01SignSecretPairingKeySerParameter that = (BLS01SignSecretPairingKeySerParameter) anObject;
			// Compare x
			if (!PairingUtils.isEqualElement(this.x, that.getX())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayX, that.byteArrayX)) {
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

		this.x = pairing.getZr().newElementFromBytes(this.byteArrayX).getImmutable();
	}
}
