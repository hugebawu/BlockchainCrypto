package cn.edu.ncepu.crypto.encryption.ibbe.del07.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.serparams.IBBEDel07MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.del07.serparams.IBBEDel07SecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibbe.genparams.IBBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Secret key generator for Delerablée IBBE scheme.
 */
public class IBBEDel07SecretKeyGenerator implements PairingKeyParameterGenerator {
    private IBBESecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBBESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        IBBEDel07MasterSecretKeySerParameter masterSecretKeyParameters = (IBBEDel07MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        IBBEDel07PublicKeySerParameter publicKeyParameters = (IBBEDel07PublicKeySerParameter)parameters.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.Zr);

        Element secretKey = masterSecretKeyParameters.getG().powZn(masterSecretKeyParameters.getGamma().add(elementId).invert()).getImmutable();

        return new IBBEDel07SecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId, secretKey);
    }
}
