package cn.edu.ncepu.crypto.encryption.abe.cpabe.llw14.serparams;

import cn.edu.ncepu.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE master secret key parameter.
 */
public class CPABELLW14MasterSecretKeySerParameter extends CPABERW13MasterSecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8044038422642169800L;

	public CPABELLW14MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
		super(pairingParameters, alpha);
	}
}
