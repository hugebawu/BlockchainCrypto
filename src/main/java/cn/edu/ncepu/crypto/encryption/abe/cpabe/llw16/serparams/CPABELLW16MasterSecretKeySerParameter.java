package cn.edu.ncepu.crypto.encryption.abe.cpabe.llw16.serparams;

import cn.edu.ncepu.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure CP-ABE master secret key parameter.
 */
public class CPABELLW16MasterSecretKeySerParameter extends CPABEHW14MasterSecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 172003267372096272L;

	public CPABELLW16MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
		super(pairingParameters, alpha);
	}
}
