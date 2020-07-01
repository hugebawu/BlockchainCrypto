package cn.edu.ncepu.crypto.encryption.ibe.gen06b.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.gen06b.serparams.IBEGen06bMasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.gen06b.serparams.IBEGen06bPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.gen06b.serparams.IBEGen06bSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Gentry CCA2-secure IBE secret key generator.
 */
public class IBEGen06bSecretKeyGenerator implements PairingKeyParameterGenerator {
    private IBESecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        IBEGen06bMasterSecretKeySerParameter masterSecretKeyParameters = (IBEGen06bMasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        IBEGen06bPublicKeySerParameter publicKeyParameters = (IBEGen06bPublicKeySerParameter)parameters.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.Zr).getImmutable();
        Element rId = pairing.getZr().newRandomElement().getImmutable();
        Element hId = publicKeyParameters.getG().powZn(rId.negate()).mul(publicKeyParameters.getH())
                .powZn(masterSecretKeyParameters.getAlpha().sub(elementId).invert()).getImmutable();
        Element rId2 = pairing.getZr().newRandomElement().getImmutable();
        Element hId2 = publicKeyParameters.getG().powZn(rId2.negate()).mul(publicKeyParameters.getH2())
                .powZn(masterSecretKeyParameters.getAlpha().sub(elementId).invert()).getImmutable();
        Element rId3 = pairing.getZr().newRandomElement().getImmutable();
        Element hId3 = publicKeyParameters.getG().powZn(rId3.negate()).mul(publicKeyParameters.getH3())
                .powZn(masterSecretKeyParameters.getAlpha().sub(elementId).invert()).getImmutable();

        return new IBEGen06bSecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId,
                rId, hId, rId2, hId2, rId3, hId3);
    }
}