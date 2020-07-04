package cn.edu.ncepu.crypto.encryption.ibe.bf01b.serparams;

import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aSecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE secret key parameter.
 */
public class IBEBF01bSecretKeySerParameter extends IBEBF01aSecretKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = -846894374317674040L;

	public IBEBF01bSecretKeySerParameter(IBEBF01aSecretKeySerParameter secretKeyParameter) {
		super(secretKeyParameter.getParameters(), secretKeyParameter.getId(), secretKeyParameter.getElementId(),
				secretKeyParameter.getD());
	}
}
