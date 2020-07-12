/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphiencryption.basicIBEHE;

import cn.edu.ncepu.crypto.homomorphiencryption.CipherText;
import it.unisa.dia.gas.jpbc.Element;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 11, 2020 6:05:18 PM
 * @ClassName IBEHECipherText
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
public class IBEHECipherText extends CipherText {
	private Element r;
	private Element g;
	// gr = g^r
	private Element gr;
	// H = hash_H(gr)
	private Element H;

	IBEHECipherText(Element U, Element V, Element r, Element g, Element gr, Element H) {
		// U = rP
		// V = M.xor(H.toBigInter())
		super(U, V);
		this.r = r.getImmutable();
		this.g = g.getImmutable();
		this.gr = gr.getImmutable();
		this.H = H.getImmutable();
	}

	@Override
	public boolean equals(Object object) {
		if (this == object) {
			return true;
		}
		if (object instanceof IBEHECipherText) {
			IBEHECipherText that = (IBEHECipherText) object;
			if (!super.equals(object)) {
				return false;
			}
			return ((this.r.isEqual(that.r)) && (this.g.isEqual(that.g)) && (this.gr.isEqual(that.gr))
					&& (this.H.isEqual(that.H)));
		}
		return false;
	}

	public Element getR() {
		return r.duplicate();
	}

	public Element getG() {
		return g.duplicate();
	}

	public Element getGr() {
		return gr.duplicate();
	}

	public Element getH() {
		return H.duplicate();
	}
}
