package cn.edu.ncepu.crypto.encryption.hibbe.llw17.serparams;

import cn.edu.ncepu.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14HeaderSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE header parameter.
 */
public class HIBBELLW17HeaderSerParameter extends HIBBELLW14HeaderSerParameter {

	/**
	 * 
	 */
	private static final long serialVersionUID = -5046187341923579606L;

	public HIBBELLW17HeaderSerParameter(PairingParameters pairingParameters, Element C0, Element C1) {
		super(pairingParameters, C0, C1);
	}
}
