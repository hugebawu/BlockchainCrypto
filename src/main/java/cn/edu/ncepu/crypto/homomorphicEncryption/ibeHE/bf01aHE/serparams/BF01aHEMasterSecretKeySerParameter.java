/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams;

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
 * @CreateData: Jul 7, 2020 12:40:03 PM
 * @ClassName BF01aHEMasterSecretKeySerParameter
 * @Description: TODO(Boneh-Franklin CPA-secure IBE based Homomorphic encryption master secret key parameter)
 */
public class BF01aHEMasterSecretKeySerParameter extends PairingKeySerParameter {

	private static final long serialVersionUID = 8444150641743284559L;
	private transient Element s;
	private final byte[] byteArrayS;

	public BF01aHEMasterSecretKeySerParameter(PairingParameters pairingParameters, Element s) {
		super(true, pairingParameters);
		this.s = s.getImmutable();
		this.byteArrayS = s.toBytes();
	}

	/**
	 * @return the s
	 */
	public Element getS() {
		return s.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof BF01aHEMasterSecretKeySerParameter) {
			BF01aHEMasterSecretKeySerParameter that = (BF01aHEMasterSecretKeySerParameter) anObject;
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

	/**
	 * TODO get master secret key s from pairing parameters and the bytes of s
	 * @param objectInputStream
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.s = pairing.getZr().newElementFromBytes(this.byteArrayS).getImmutable();
	}

}
