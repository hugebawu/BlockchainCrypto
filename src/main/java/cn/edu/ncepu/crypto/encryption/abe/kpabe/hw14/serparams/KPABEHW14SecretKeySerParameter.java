package cn.edu.ncepu.crypto.encryption.abe.kpabe.hw14.serparams;

import java.util.Map;

import cn.edu.ncepu.crypto.access.AccessControlParameter;
import cn.edu.ncepu.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE secret key parameter.
 */
public class KPABEHW14SecretKeySerParameter extends KPABERW13SecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7167009365061844755L;

	public KPABEHW14SecretKeySerParameter(PairingParameters pairingParameters,
			AccessControlParameter accessControlParameter, Map<String, Element> K0s, Map<String, Element> K1s,
			Map<String, Element> K2s) {
		super(pairingParameters, accessControlParameter, K0s, K1s, K2s);
	}
}
