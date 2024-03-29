package cn.edu.ncepu.crypto.encryption.abe.kpabe.llw16.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14IntermediateSerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE intermediate ciphertext parameter.
 */
public class KPABELLW16IntermediateSerParameter extends KPABEHW14IntermediateSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3209646301744716827L;
	private final byte[] chameleonHash;
	private final byte[] r;

	private final AsymmetricKeySerParameter chameleonHashPublicKey;
	private final AsymmetricKeySerParameter chameleonHashSecretKey;

	private transient Element C01;
	private final byte[] byteArrayC01;

	private transient Element C02;
	private final byte[] byteArrayC02;

	public KPABELLW16IntermediateSerParameter(PairingParameters parameters, int n, byte[] chameleonHash, byte[] r,
			AsymmetricKeySerParameter chameleonHashPublicKey, AsymmetricKeySerParameter chameleonHashSecretKey,
			Element C01, Element C02, Element sessionKey, Element s, Element C0, Element[] rs, Element[] xs,
			Element[] C1s, Element[] C2s) {
		super(parameters, n, sessionKey, s, C0, rs, xs, C1s, C2s);
		this.chameleonHash = chameleonHash;
		this.r = r;
		this.chameleonHashPublicKey = chameleonHashPublicKey;
		this.chameleonHashSecretKey = chameleonHashSecretKey;

		this.C01 = C01.getImmutable();
		this.byteArrayC01 = this.C01.toBytes();

		this.C02 = C02.getImmutable();
		this.byteArrayC02 = this.C02.toBytes();
	}

	public byte[] getChameleonHash() {
		return this.chameleonHash;
	}

	public byte[] getR() {
		return this.r;
	}

	public AsymmetricKeySerParameter getChameleonHashPublicKey() {
		return this.chameleonHashPublicKey;
	}

	public AsymmetricKeySerParameter getChameleonHashSecretKey() {
		return this.chameleonHashSecretKey;
	}

	public Element getC01() {
		return this.C01.duplicate();
	}

	public Element getC02() {
		return this.C02.duplicate();
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof KPABELLW16IntermediateSerParameter) {
			KPABELLW16IntermediateSerParameter that = (KPABELLW16IntermediateSerParameter) anObject;
			if (!PairingUtils.isEqualElement(this.C01, that.C01)) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayC01, that.byteArrayC01)) {
				return false;
			}
			if (!PairingUtils.isEqualElement(this.C02, that.C02)) {
				return false;
			}
			if (!Arrays.equals(this.byteArrayC02, that.byteArrayC02)) {
				return false;
			}
			// Compare chameleon hash key
			if (!(this.chameleonHashSecretKey.equals(that.chameleonHashSecretKey))) {
				return false;
			}
			if (!(this.chameleonHashPublicKey.equals(that.chameleonHashPublicKey))) {
				return false;
			}
			// Compare chameleon hash
			return Arrays.equals(this.r, that.r) && Arrays.equals(this.chameleonHash, that.chameleonHash)
					&& super.equals(anObject);
		}
		return false;
	}

	private void readObject(java.io.ObjectInputStream objectInputStream)
			throws java.io.IOException, ClassNotFoundException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.getParameters());
		this.C01 = pairing.getG1().newElementFromBytes(this.byteArrayC01).getImmutable();
		this.C02 = pairing.getG1().newElementFromBytes(this.byteArrayC02).getImmutable();
	}
}
