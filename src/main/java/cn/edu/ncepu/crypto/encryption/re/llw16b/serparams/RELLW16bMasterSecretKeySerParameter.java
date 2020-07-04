package cn.edu.ncepu.crypto.encryption.re.llw16b.serparams;

import cn.edu.ncepu.crypto.encryption.re.llw16a.serparams.RELLW16aMasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE master secret key parameter.
 */
public class RELLW16bMasterSecretKeySerParameter extends RELLW16aMasterSecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 2560407705530315132L;

	public RELLW16bMasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Element b,
			Element h) {
		super(pairingParameters, alpha, b, h);
	}
}
