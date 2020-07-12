/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphiencryption.ibeHE.bf01aHE.serparams;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jul 7, 2020 1:07:14 PM
 * @ClassName BF01aHEPublicKeySerParameter
 * @Description: TODO(Boneh-Franklin CPA-secure IBE based homomorphic encryption system public key parameter.)
 */
public class BF01aHEPublicKeySerParameter extends PairingKeySerParameter {
	private static final long serialVersionUID = 8512049019183179324L;
	private transient Element P;
	private final byte[] byteArrayP;

	private transient Element sP; // Ppub
	private final byte[] byteArraySP;

	public BF01aHEPublicKeySerParameter(PairingParameters pairingParameters, Element P, Element sP) {
		super(false, pairingParameters);
		this.P = P.getImmutable();
		this.byteArrayP = this.P.toBytes();

		this.sP = sP.getImmutable();
		this.byteArraySP = this.sP.toBytes();
	}

	public Element getP() {
		return P.duplicate();
	}

	public Element getsP() {
		return sP.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof BF01aHEPublicKeySerParameter) {
			BF01aHEPublicKeySerParameter that = (BF01aHEPublicKeySerParameter) anObject;
			// Compare P
			if (!PairingUtils.isEqualElement(this.P, that.P)) {
				return false;
			}
			if (!Arrays.equals(this.byteArraySP, that.byteArraySP)) {
				return false;
			}
			// Compare sP
			if (!PairingUtils.isEqualElement(this.sP, that.sP)) {
				return false;
			}
			if (!Arrays.equals(this.byteArraySP, that.byteArraySP)) {
				return false;
			}
			// Compare Pairing Parameters
			return this.getParameters().toString().equals(that.getParameters().toString());
		}
		return false;
	}

	private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.P = pairing.getG1().newElementFromBytes(this.byteArrayP).getImmutable();
		this.sP = pairing.getG1().newElementFromBytes(this.byteArraySP).getImmutable();
	}
}
