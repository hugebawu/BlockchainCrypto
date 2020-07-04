package cn.edu.ncepu.crypto.encryption.abe.cpabe.llw16.serparams;

import cn.edu.ncepu.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure CP-ABE public key parameter.
 */
public class CPABELLW16PublicKeySerParameter extends CPABEHW14PublicKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3526701590071208055L;

	public CPABELLW16PublicKeySerParameter(PairingParameters parameters, Element g, Element u, Element h, Element w,
			Element v, Element eggAlpha) {
		super(parameters, g, u, h, w, v, eggAlpha);
	}
}
