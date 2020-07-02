package cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE public key / master secret key pair generator.
 */
public class IBEBF01aKeyPairGenerator implements PairingKeyPairGenerator {
	private IBEKeyPairGenerationParameter params;

	@Override
	public void init(KeyGenerationParameters keyGenerationParameters) {
		this.params = (IBEKeyPairGenerationParameter) keyGenerationParameters;
	}

	@Override
	public PairingKeySerPair generateKeyPair() {
		Pairing pairing = PairingFactory.getPairing(this.params.getPairingParameters());
		Element g = pairing.getG1().newRandomElement().getImmutable();
		Element s = pairing.getZr().newRandomElement().getImmutable();
		Element gs = g.powZn(s).getImmutable();

		return new PairingKeySerPair(new IBEBF01aPublicKeySerParameter(this.params.getPairingParameters(), g, gs),
				new IBEBF01aMasterSecretKeySerParameter(this.params.getPairingParameters(), s));
	}
}
