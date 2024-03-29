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
 * Boneh-Lynn-Shacham signature public key parameters.
 */
class BLS01SignPublicPairingKeySerParameter extends PairingKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -143402761418965579L;
	private transient Element g;
	private final byte[] byteArrayG;

	private transient Element v;
	private final byte[] byteArrayV;

	BLS01SignPublicPairingKeySerParameter(PairingParameters parameters, Element g, Element v) {
		super(false, parameters);
		this.g = g.getImmutable();
		this.byteArrayG = this.g.toBytes();

		this.v = v.getImmutable();
		this.byteArrayV = this.v.toBytes();
	}

	public Element getG() {
		return this.g.duplicate();
	}

	public Element getV() {
		return this.v.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof BLS01SignPublicPairingKeySerParameter) {
			BLS01SignPublicPairingKeySerParameter that = (BLS01SignPublicPairingKeySerParameter) anObject;
			// Compare g
			if (!PairingUtils.isEqualElement(this.g, that.getG())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
				return false;
			}
			// Compare v
			if (!PairingUtils.isEqualElement(this.v, that.getV())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayV, that.byteArrayV)) {
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

		this.g = pairing.getG2().newElementFromBytes(this.byteArrayG).getImmutable();
		this.v = pairing.getG2().newElementFromBytes(this.byteArrayV).getImmutable();
	}
}