/**
 * 
 */
package cn.edu.ncepu.crypto.HE.ibeHE.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 11:21:46 PM
 * @ClassName IBEHEDecryptionGenerationParameter
 * @Description: TODO(Boneh-Franklin CPA-secure IBE-Based homomorphic encryption decryption generation parameter.)
 */
public class IBEHEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
	// user id used during decryption
	String id;

	public IBEHEDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter secretKeyParameter, String id, PairingCipherSerParameter ciphertextParameter) {
		super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
		this.id = id;
	}

	public String getId() {
		return id;
	}

}
