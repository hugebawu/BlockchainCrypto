package cn.edu.ncepu.crypto.encryption.abe.kpabe.llw14.serparams;

import cn.edu.ncepu.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Liu-Liu-Wu-14 CCA2-secure KP-ABE master secret key parameter.
 */
public class KPABELLW14MasterSecretKeySerParameter extends KPABERW13MasterSecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -1792233249866231106L;

	public KPABELLW14MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
		super(pairingParameters, alpha);
	}
}
