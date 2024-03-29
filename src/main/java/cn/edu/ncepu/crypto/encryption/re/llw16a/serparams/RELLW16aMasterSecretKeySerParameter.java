package cn.edu.ncepu.crypto.encryption.re.llw16a.serparams;

import cn.edu.ncepu.crypto.encryption.re.lsw10a.serparams.RELSW10aMasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CPA-secure RE master secret key parameter.
 */
public class RELLW16aMasterSecretKeySerParameter extends RELSW10aMasterSecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5669202552810388646L;

	public RELLW16aMasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Element b,
			Element h) {
		super(pairingParameters, alpha, b, h);
	}
}
