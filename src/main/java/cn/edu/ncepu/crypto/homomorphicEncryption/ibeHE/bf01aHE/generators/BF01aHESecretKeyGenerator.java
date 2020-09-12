/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams.BF01aHEMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.serparams.BF01aHESecretKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.genparams.IBEHESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jul 7, 2020 2:10:55 PM
 * @ClassName BF01aHESecretKeyGenerator
 * @Description:  (这里用一句话描述这个方法的作用)
 */
public class BF01aHESecretKeyGenerator implements PairingKeyParameterGenerator {
	IBEHESecretKeyGenerationParameter parameters;

	@Override
	public void init(KeyGenerationParameters keyGenerationParameters) {
		this.parameters = (IBEHESecretKeyGenerationParameter) keyGenerationParameters;
	}

	@Override
	public PairingKeySerParameter generateKey() {
		BF01aHEMasterSecretKeySerParameter masterSecretKeyParameters = (BF01aHEMasterSecretKeySerParameter) parameters
				.getMasterSecretKeyParameter();

		Pairing pairing = PairingFactory.getPairing(masterSecretKeyParameters.getParameters());
		Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.G1)
				.getImmutable();
		Element d = elementId.powZn(masterSecretKeyParameters.getS()).getImmutable();
		return new BF01aHESecretKeySerParameter(masterSecretKeyParameters.getParameters(), parameters.getId(),
				elementId, d);
	}

}
