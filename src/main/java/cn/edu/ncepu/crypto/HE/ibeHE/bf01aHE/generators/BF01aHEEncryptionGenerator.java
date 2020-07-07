/**
 * 
 */
package cn.edu.ncepu.crypto.HE.ibeHE.bf01aHE.generators;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;

import cn.edu.ncepu.crypto.HE.ibeHE.bf01aHE.serparams.BF01aHECiphertextSerParameter;
import cn.edu.ncepu.crypto.HE.ibeHE.bf01aHE.serparams.BF01aHEPublicKeySerParameter;
import cn.edu.ncepu.crypto.HE.ibeHE.genparams.IBEHEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
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
 * @Description: TODO(这里用一句话描述这个方法的作用)
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
		String id = this.params.getId();
		Element elementId = PairingUtils.hash_G(pairing.getG1(), id);
		Element r = pairing.getZr().newRandomElement().getImmutable();
		Element U = publicKeyParameter.getP().powZn(r).getImmutable();
		this.g = pairing.pairing(elementId, publicKeyParameter.getsP()).getImmutable();
		this.g = g.powZn(r).getImmutable();
		BigInteger V = this.params.getBImessage().xor(PairingUtils.hash_H(pairing.getGT(), this.g).toBigInteger());
		return new BF01aHECiphertextSerParameter(pairingParameters, U, V);
	}

}
