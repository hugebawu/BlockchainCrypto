package cn.edu.ncepu.crypto.encryption.ibe.gen06a.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.gen06a.serparams.IBEGen06aMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.gen06a.serparams.IBEGen06aPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.gen06a.serparams.IBEGen06aSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE secret key generator.
 */
public class IBEGen06aSecretKeyGenerator implements PairingKeyParameterGenerator {
	private IBESecretKeyGenerationParameter parameters;

	public void init(KeyGenerationParameters keyGenerationParameters) {
		this.parameters = (IBESecretKeyGenerationParameter) keyGenerationParameters;
	}

	public PairingKeySerParameter generateKey() {
		IBEGen06aMasterSecretKeySerParameter masterSecretKeyParameters = (IBEGen06aMasterSecretKeySerParameter) parameters
				.getMasterSecretKeyParameter();
		IBEGen06aPublicKeySerParameter publicKeyParameters = (IBEGen06aPublicKeySerParameter) parameters
				.getPublicKeyParameter();

		Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
		Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.Zr)
				.getImmutable();
		Element rId = pairing.getZr().newRandomElement().getImmutable();
		Element hId = publicKeyParameters.getG().powZn(rId.negate()).mul(publicKeyParameters.getH())
				.powZn(masterSecretKeyParameters.getAlpha().sub(elementId).invert()).getImmutable();
		return new IBEGen06aSecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId,
				rId, hId);
	}
}
