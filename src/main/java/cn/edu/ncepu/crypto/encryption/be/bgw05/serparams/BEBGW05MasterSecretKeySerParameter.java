package cn.edu.ncepu.crypto.encryption.be.bgw05.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE master secret key parameter.
 */
public class BEBGW05MasterSecretKeySerParameter extends PairingKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8309983432668906317L;
	private transient Element gamma;
	private final byte[] byteArrayGamma;

	public BEBGW05MasterSecretKeySerParameter(PairingParameters pairingParameters, Element gamma) {
		super(true, pairingParameters);

		this.gamma = gamma.getImmutable();
		this.byteArrayGamma = this.gamma.toBytes();
	}

	public Element getGamma() {
		return this.gamma.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof BEBGW05MasterSecretKeySerParameter) {
			BEBGW05MasterSecretKeySerParameter that = (BEBGW05MasterSecretKeySerParameter) anObject;
			// compare y
			if (!(PairingUtils.isEqualElement(this.gamma, that.gamma))) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayGamma, that.byteArrayGamma)) {
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
		this.gamma = pairing.getZr().newElementFromBytes(this.byteArrayGamma).getImmutable();
	}
}