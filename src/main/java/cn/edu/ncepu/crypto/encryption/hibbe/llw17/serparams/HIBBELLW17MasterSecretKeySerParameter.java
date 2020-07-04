package cn.edu.ncepu.crypto.encryption.hibbe.llw17.serparams;

import cn.edu.ncepu.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE master secret key parameter.
 */
public class HIBBELLW17MasterSecretKeySerParameter extends HIBBELLW14MasterSecretKeySerParameter {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5936694434602866160L;

	public HIBBELLW17MasterSecretKeySerParameter(PairingParameters pairingParameters, Element gAlpha) {
		super(pairingParameters, gAlpha);
	}
}