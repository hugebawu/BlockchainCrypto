package cn.edu.ncepu.crypto.encryption.hibbe.llw16b.serparams;

import cn.edu.ncepu.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aMasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE master secret key parameter.
 */
public class HIBBELLW16bMasterSecretKeySerParameter extends HIBBELLW16aMasterSecretKeySerParameter {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3514740453824135480L;

	public HIBBELLW16bMasterSecretKeySerParameter(PairingParameters pairingParameters, Element g2Alpha) {
		super(pairingParameters, g2Alpha);
	}
}