/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicencryption.ibeHE.bf01aHE.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.homomorphicencryption.ibeHE.bf01aHE.serparams.BF01aHEMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicencryption.ibeHE.bf01aHE.serparams.BF01aHEPublicKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicencryption.ibeHE.genparams.IBEHEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jul 7, 2020 12:21:15 PM
 * @ClassName BF01aHEKeyPairGenerator
 * @Description: TODO(Boneh-Franklin CPA-secure IBE based Homomorphic encryption system public key / master secret key pair generator.)
 */
public class BF01aHEKeyPairGenerator implements PairingKeyPairGenerator {
	private IBEHEKeyPairGenerationParameter params;

	@Override
	public void init(KeyGenerationParameters param) {
		this.params = (IBEHEKeyPairGenerationParameter) param;
	}

	@Override
	public PairingKeySerPair generateKeyPair() {
		Pairing pairing = PairingFactory.getPairing(this.params.getPairingParameters());
		// P which belongs to E/Fq, can also regard as a generator of the E/Fq
		Element P = pairing.getG1().newRandomElement().getImmutable();
		// master secret key s
		Element s = pairing.getZr().newRandomElement().getImmutable();
		// Ppub=sP
		Element sP = P.powZn(s).getImmutable();
		return new PairingKeySerPair(new BF01aHEPublicKeySerParameter(this.params.getPairingParameters(), P, sP),
				new BF01aHEMasterSecretKeySerParameter(this.params.getPairingParameters(), s));
	}

}
