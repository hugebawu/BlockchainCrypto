/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 10:01:04 PM
 * @ClassName BF01aHECiphertextSerParameter
 * @Description: TODO(Boneh-Franklin CPA-secure IBE based homomorphic ciphertext parameter.)
 */
public class BF01aHECiphertextSerParameter extends PairingCipherSerParameter {

	private static final long serialVersionUID = -2619864414488802090L;
	private transient Element U;
	private final byte[] byteArrayU;

	private transient Element V;
	private final byte[] byteArrayV;

	public BF01aHECiphertextSerParameter(PairingParameters parameters, Element U, Element V) {
		super(parameters);
		this.U = U.getImmutable();
		this.byteArrayU = this.U.toBytes();
		this.V = V.getImmutable();
		this.byteArrayV = this.V.toBytes();
	}

	public Element getU() {
		return U.duplicate();
	}

	public Element getV() {
		return V.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof BF01aHECiphertextSerParameter) {
			BF01aHECiphertextSerParameter that = (BF01aHECiphertextSerParameter) anObject;
			if (!PairingUtils.isEqualElement(this.U, that.U)) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayU, that.byteArrayU)) {
				return false;
			}
			if (!PairingUtils.isEqualElement(this.V, that.V)) {
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

	private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.U = pairing.getG1().newElementFromBytes(this.byteArrayU).getImmutable();
		this.V = pairing.getGT().newElementFromBytes(this.byteArrayV).getImmutable();
	}
}
