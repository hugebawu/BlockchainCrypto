/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphiencryption.ibeHE.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 2:15:17 PM
 * @ClassName IBEHESecretKeyGenerationParameter
 * @Description: TODO(IBE-Based homomorphic encryption user secret key generation parameter.)
 */
public class IBEHESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
	// user id used for generating the user secret key
	private String id;

	public IBEHESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter masterSecretKeyParameter, String id) {
		super(publicKeyParameter, masterSecretKeyParameter);
		this.id = id;
	}

	public String getId() {
		return id;
	}

}
