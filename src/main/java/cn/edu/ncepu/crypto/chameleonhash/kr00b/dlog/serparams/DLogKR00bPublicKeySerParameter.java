package cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.serparams;

import java.math.BigInteger;

import cn.edu.ncepu.crypto.algebra.serparams.SecurePrimeSerParameter;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin public key parameters
 */
public class DLogKR00bPublicKeySerParameter extends DLogKR00bKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3565981306694014994L;
	private final BigInteger y;

	public DLogKR00bPublicKeySerParameter(BigInteger y, SecurePrimeSerParameter params) {
		super(false, params);
		this.y = y;
	}

	public BigInteger getY() {
		return y;
	}

	@Override
	public boolean equals(Object anOjbect) {
		if (this == anOjbect) {
			return true;
		}
		if (anOjbect instanceof DLogKR00bPublicKeySerParameter) {
			DLogKR00bPublicKeySerParameter that = (DLogKR00bPublicKeySerParameter) anOjbect;
			// Compare y
			if (!this.y.equals(that.getY())) {
				return false;
			}
			// Compare SecurePrimeSerParameter
			return this.getParameters().equals(that.getParameters());
		}
		return false;
	}
}
