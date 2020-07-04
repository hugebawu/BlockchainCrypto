package cn.edu.ncepu.crypto.encryption.ibe.bf01b.serparams;

import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE master secret key parameter.
 */
public class IBEBF01bMasterSecretKeySerParameter extends IBEBF01aMasterSecretKeySerParameter {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7319817067689485938L;

	public IBEBF01bMasterSecretKeySerParameter(IBEBF01aMasterSecretKeySerParameter masterSecretKeyParameter) {
		super(masterSecretKeyParameter.getParameters(), masterSecretKeyParameter.getS());
	}
}
