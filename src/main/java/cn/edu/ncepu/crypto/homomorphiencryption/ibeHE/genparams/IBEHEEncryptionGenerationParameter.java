/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphiencryption.ibeHE.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 4:01:54 PM
 * @ClassName IBEHEEncryptionGenerationParameter
 * @Description: TODO(IBE-Based homomorphic encryption ciphertext generation parameter.)
 */
public class IBEHEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
	private String id;

	public IBEHEEncryptionGenerationParameter(String id, PairingKeySerParameter publicKeyParameter, Element message) {
		super(publicKeyParameter, message);
		setId(id);
	}

	public String getId() {
		return id;
	}

	private void setId(String id) {
		this.id = id;
	}

}
