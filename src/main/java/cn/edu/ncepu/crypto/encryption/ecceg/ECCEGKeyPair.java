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
 * @CreateData: Jul 14, 2020 4:12:58 PM
 * @ClassName ECCEGKeyPair
 * @Description:  (这里用一句话描述这个方法的作用)
 */
@SuppressWarnings("rawtypes")
public class ECCEGKeyPair {

	ZrElement privateKey;
	CurveElement publicKey;

	public ECCEGKeyPair(ZrElement privateKey, CurveElement publicKey) {
		setPrivateKey(privateKey);
		setPublicKey(publicKey);
	}

	public void setPrivateKey(ZrElement privateKey) {
		this.privateKey = (ZrElement) privateKey.getImmutable();
	}

	public ZrElement getPrivateKey() {
		return privateKey.duplicate();
	}

	public void setPublicKey(CurveElement publicKey) {
		this.publicKey = (CurveElement) publicKey.getImmutable();
	}

	public CurveElement getPublicKey() {
		return publicKey.duplicate();
	}

}
