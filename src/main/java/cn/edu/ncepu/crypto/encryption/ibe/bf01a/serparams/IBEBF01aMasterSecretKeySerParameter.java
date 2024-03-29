package cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE master secret key parameter.
 */
public class IBEBF01aMasterSecretKeySerParameter extends PairingKeySerParameter {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4430031125108786921L;
	private transient Element s;
	private final byte[] byteArrayS;

	public IBEBF01aMasterSecretKeySerParameter(PairingParameters pairingParameters, Element s) {
		super(true, pairingParameters);
		this.s = s.getImmutable();
		this.byteArrayS = this.s.toBytes();
	}

	public Element getS() {
		return this.s.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof IBEBF01aMasterSecretKeySerParameter) {
			IBEBF01aMasterSecretKeySerParameter that = (IBEBF01aMasterSecretKeySerParameter) anObject;
			// Compare alpha
			if (!(PairingUtils.isEqualElement(this.s, that.s))) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayS, that.byteArrayS)) {
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
		this.s = pairing.getZr().newElementFromBytes(this.byteArrayS).getImmutable();
	}
}
