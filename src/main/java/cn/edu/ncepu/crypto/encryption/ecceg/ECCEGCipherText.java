/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.ecceg;

import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 14, 2020 4:28:54 PM
 * @ClassName ECCEGCipherText
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
@SuppressWarnings("rawtypes")
public class ECCEGCipherText {
	private CurveElement U;
	private CurveElement V;
	private ZrElement r;

	public ECCEGCipherText(CurveElement U, CurveElement V, ZrElement r) {
		this.U = (CurveElement) U.getImmutable();
		this.V = (CurveElement) V.getImmutable();
		this.r = r;
	}

	public CurveElement getU() {
		return (CurveElement) U.getImmutable();
	}

	public CurveElement getV() {
		return (CurveElement) V.getImmutable();
	}

	public ZrElement getR() {
		return r;
	}

}
