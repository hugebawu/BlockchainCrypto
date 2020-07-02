package cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE secret key generator.
 */
public class IBEBF01aSecretKeyGenerator implements PairingKeyParameterGenerator {
	private IBESecretKeyGenerationParameter parameters;

	@Override
	public void init(KeyGenerationParameters keyGenerationParameters) {
		this.parameters = (IBESecretKeyGenerationParameter) keyGenerationParameters;
	}

	@Override
	public PairingKeySerParameter generateKey() {
		IBEBF01aMasterSecretKeySerParameter masterSecretKeyParameters = (IBEBF01aMasterSecretKeySerParameter) parameters
				.getMasterSecretKeyParameter();
		IBEBF01aPublicKeySerParameter publicKeyParameters = (IBEBF01aPublicKeySerParameter) parameters
				.getPublicKeyParameter();

		Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
		Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.G1)
				.getImmutable();
		Element d = elementId.powZn(masterSecretKeyParameters.getS()).getImmutable();
		return new IBEBF01aSecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId, d);
	}
}
