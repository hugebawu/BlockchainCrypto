package cn.edu.ncepu.crypto.encryption.abe.cpabe.hw14.serparams;

import cn.edu.ncepu.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE public key parameter.
 */
public class CPABEHW14PublicKeySerParameter extends CPABERW13PublicKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -3567597338889603946L;

	public CPABEHW14PublicKeySerParameter(PairingParameters parameters, Element g, Element u, Element h, Element w,
			Element v, Element eggAlpha) {
		super(parameters, g, u, h, w, v, eggAlpha);
	}
}
