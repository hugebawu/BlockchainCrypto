/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams.BF01aHECiphertextSerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams.BF01aHESecretKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.genparams.IBEHEDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 11:11:19 PM
 * @ClassName BF01aHEDecryptionGenerator
 * @Description:  (Boneh-Franklin CPA-secure IBE based homomorphic decryption generator.)
 */
public class BF01aHEDecryptionGenerator implements PairingDecryptionGenerator {
	IBEHEDecryptionGenerationParameter params;

	private Element g;

	@Override
	public void init(CipherParameters params) {
		this.params = (IBEHEDecryptionGenerationParameter) params;
	}

	@Override
	public Element recoverMessage() throws InvalidCipherTextException {
		BF01aHESecretKeySerParameter secretKeyParameter = (BF01aHESecretKeySerParameter) this.params
				.getSecretKeyParameter();

		BF01aHECiphertextSerParameter ciphertextParameter = (BF01aHECiphertextSerParameter) this.params
				.getCiphertextParameter();
		Pairing pairing = PairingFactory.getPairing(secretKeyParameter.getParameters());

		Element elementIdCT = PairingUtils.hash_G(pairing, this.params.getId());
		if (!secretKeyParameter.getElementId().equals(elementIdCT)) {
			throw new InvalidCipherTextException(
					"Secret Key identity vector does not match Ciphertext identity vector");
		}
		this.g = pairing.pairing(secretKeyParameter.getD(), ciphertextParameter.getU()).getImmutable();
		return ciphertextParameter.getV().sub(PairingUtils.hash_H(pairing, this.g));
	}

}
