package cn.edu.ncepu.crypto.encryption.ibe.bf01b.serparams;

import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE public key parameter.
 */
public class IBEBF01bPublicKeySerParameter extends IBEBF01aPublicKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7781413013345794180L;

	public IBEBF01bPublicKeySerParameter(IBEBF01aPublicKeySerParameter publicKeyParameter) {
		super(publicKeyParameter.getParameters(), publicKeyParameter.getG(), publicKeyParameter.getGs());
	}
}
