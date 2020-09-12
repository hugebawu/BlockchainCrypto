/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 1:35:49 PM
 * @ClassName IBEHEKeyPairGenerationParameter
 * @Description:  (IBE based homomorphic system public key / master secret key pair generation parameter.)
 */
public class IBEHEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {

	public IBEHEKeyPairGenerationParameter(PairingParameters pairingParameters) {
		super(pairingParameters);
	}

}
