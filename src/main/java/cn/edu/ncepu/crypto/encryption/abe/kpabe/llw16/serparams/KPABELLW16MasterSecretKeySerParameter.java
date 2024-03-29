package cn.edu.ncepu.crypto.encryption.abe.kpabe.llw16.serparams;

import cn.edu.ncepu.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE master secret key parameter.
 */
public class KPABELLW16MasterSecretKeySerParameter extends KPABEHW14MasterSecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8747606918943918572L;

	public KPABELLW16MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
		super(pairingParameters, alpha);
	}
}
