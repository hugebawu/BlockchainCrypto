/**
 * 
 */
package cn.edu.ncepu.crypto.HE.ibeHE.bf01aHE.serparams;

import java.math.BigInteger;
import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 10:01:04 PM
 * @ClassName BF01aHECiphertextSerParameter
 * @Description: TODO(Boneh-Franklin CPA-secure IBE based homomorphic ciphertext parameter.)
 */
public class BF01aHECiphertextSerParameter extends PairingCipherSerParameter {
	private static final long serialVersionUID = -7776255631432449405L;
	private transient Element U;
	private final byte[] byteArrayU;

	private transient BigInteger V;
	private final byte[] byteArrayV;

	public BF01aHECiphertextSerParameter(PairingParameters parameters, Element U, BigInteger V) {
		super(parameters);
		this.U = U.getImmutable();
		this.byteArrayU = this.U.toBytes();
		this.V = V;
		this.byteArrayV = V.toByteArray();
	}

	public Element getU() {
		return U.duplicate();
	}

	public byte[] getByteArrayU() {
		return byteArrayU;
	}

	public BigInteger getV() {
		return V;
	}

	public byte[] getByteArrayV() {
		return byteArrayV;
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
			if (!this.V.equals(that.V)) {
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

}
