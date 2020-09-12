/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.eccegHE;

import cn.edu.ncepu.crypto.homomorphicEncryption.CipherText;
import it.unisa.dia.gas.jpbc.Element;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 11, 2020 6:05:18 PM
 * @ClassName IBEHECipherText
 * @Description:  (这里用一句话描述这个方法的作用)
 */
public class ECElgamalHECipherText extends CipherText {
	private Element r;
	private Element P;
	// Q = dP
	private Element Q;

	ECElgamalHECipherText(Element U, Element V, Element r, Element P, Element Q) {
		// U = rP
		// V = M + (rQ)
		super(U, V);
		this.r = r.getImmutable();
		this.P = P.getImmutable();
		this.Q = Q.getImmutable();
	}

	@Override
	public boolean equals(Object object) {
		if (this == object) {
			return true;
		}
		if (object instanceof ECElgamalHECipherText) {
			ECElgamalHECipherText that = (ECElgamalHECipherText) object;
			if (!super.equals(object)) {
				return false;
			}
			return ((this.r.isEqual(that.r)) && (this.P.isEqual(that.P)) && (this.Q.isEqual(that.Q)));
		}
		return false;
	}

	public Element getR() {
		return r;
	}

	public Element getP() {
		return P;
	}

	public Element getQ() {
		return Q;
	}

}
