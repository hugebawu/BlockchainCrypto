/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.generators;

import org.bouncycastle.crypto.CipherParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams.BF01aHECiphertextSerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams.BF01aHEPublicKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.genparams.IBEHEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 7, 2020 4:00:16 PM
 * @ClassName BF01aHEEncryptionGenerator
 * @Description:  (这里用一句话描述这个方法的作用)
 */
public class BF01aHEEncryptionGenerator implements PairingEncryptionGenerator {
	private IBEHEEncryptionGenerationParameter params;
	private BF01aHEPublicKeySerParameter publicKeyParameter;
	private Element g;

	@Override
	public void init(CipherParameters params) {
		this.params = (IBEHEEncryptionGenerationParameter) params;
		this.publicKeyParameter = (BF01aHEPublicKeySerParameter) this.params.getPublicKeyParameter();
	}

	@Override
	public PairingCipherSerParameter generateCiphertext() {
		PairingParameters pairingParameters = publicKeyParameter.getParameters();
		Pairing pairing = PairingFactory.getPairing(pairingParameters);
		Element elementId = PairingUtils.hash_G(pairing, this.params.getId());
		Element r = pairing.getZr().newRandomElement().getImmutable();
		Element U = publicKeyParameter.getP().powZn(r).getImmutable();
		this.g = pairing.pairing(elementId, publicKeyParameter.getsP()).powZn(r).getImmutable();
		Element V = this.params.getMessage().add(PairingUtils.hash_H(pairing, this.g)).getImmutable();
		return new BF01aHECiphertextSerParameter(pairingParameters, U, V);
	}

}
