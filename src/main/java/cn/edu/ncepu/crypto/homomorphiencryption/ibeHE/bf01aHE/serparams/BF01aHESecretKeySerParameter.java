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
 * @CreateData: Jul 7, 2020 3:20:44 PM
 * @ClassName BF01aHESecretKeySerParameter
 * @Description: TODO(Boneh-Franklin CPA-secure IBE based homomorphic secret key parameter.)
 */
public class BF01aHESecretKeySerParameter extends PairingKeySerParameter {
	private static final long serialVersionUID = -1831692851746910995L;
	// user id used for generating the secret key(i.e., the owner of the secret key)
	private final String id;
	// user id that mapped into a element of the group
	private transient Element elementId;
	private final byte[] byteArrayElementId;

	// user secret key
	private transient Element d;
	private final byte[] byteArrayD;

	public BF01aHESecretKeySerParameter(PairingParameters pairingParameters, String id, Element elementId, Element d) {
		super(true, pairingParameters);
		this.d = d.getImmutable();
		this.byteArrayD = this.d.toBytes();

		this.id = id;
		this.elementId = elementId.getImmutable();
		this.byteArrayElementId = this.elementId.toBytes();
	}

	public String getId() {
		return id;
	}

	public Element getElementId() {
		return elementId;
	}

	public Element getD() {
		return d;
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof BF01aHESecretKeySerParameter) {
			BF01aHESecretKeySerParameter that = (BF01aHESecretKeySerParameter) anObject;
			// Compare id
			if (!this.id.equals(that.getId())) {
				return false;
			}
			// Compare elementId
			if (!PairingUtils.isEqualElement(this.elementId, that.getElementId())) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayElementId, that.byteArrayElementId)) {
				return false;
			}
			// Compare d
			if (!PairingUtils.isEqualElement(this.d, that.d)) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayD, that.byteArrayD)) {
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
		this.elementId = pairing.getG1().newElementFromBytes(this.byteArrayElementId).getImmutable();
		this.d = pairing.getG1().newElementFromBytes(this.byteArrayD).getImmutable();
	}
}
