/**
 * 
 */
package cn.edu.ncepu.crypto.HE;

import it.unisa.dia.gas.jpbc.Element;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 11, 2020 6:06:28 PM
 * @ClassName CipherText
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
public abstract class CipherText {
	private Element U;
	private Element V;

	public CipherText(Element U, Element V) {
		this.U = U.getImmutable();
		this.V = V.getImmutable();
	}

	public Element getU() {
		return U.duplicate();
	}

	public Element getV() {
		return V.duplicate();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof CipherText) {
			CipherText that = (CipherText) obj;
			return (this.U.isEqual(that.U)) && (this.V.isEqual(that.V));
		}
		return false;
	}
}
