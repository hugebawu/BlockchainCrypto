package cn.edu.ncepu.crypto.encryption.sepe.serparams;

import java.util.Arrays;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Self-extractable predicate encryption header parameter.
 */
public class SEPEHeaderParameter extends PairingCipherSerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 700530996421720423L;
	private final PairingCipherSerParameter ct_y;
	private byte[] ct_k;

	public SEPEHeaderParameter(PairingCipherSerParameter ct_y, byte[] ct_k) {
		super(ct_y.getParameters());
		this.ct_y = ct_y;
		this.ct_k = ct_k;
	}

	public PairingCipherSerParameter getCtY() {
		return this.ct_y;
	}

	public byte[] getCtK() {
		return this.ct_k;
	}

	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof SEPEHeaderParameter) {
			SEPEHeaderParameter that = (SEPEHeaderParameter) anObject;
			return Arrays.equals(this.ct_k, that.ct_k)
					&& this.getParameters().toString().equals(that.getParameters().toString())
					&& this.ct_y.equals(that.ct_y);
		}
		return false;
	}
}