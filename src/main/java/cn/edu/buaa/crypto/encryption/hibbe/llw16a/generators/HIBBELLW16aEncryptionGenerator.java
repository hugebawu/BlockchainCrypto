package cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE encryption generator.
 */
public class HIBBELLW16aEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private HIBBEEncryptionGenerationParameter params;
    private HIBBELLW16aPublicKeySerParameter publicKeyParameter;

    private Element sessionKey;
    private Element C0;
    private Element C1;

    public void init(CipherParameters params) {
        this.params = (HIBBEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (HIBBELLW16aPublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        HIBBELLW16aPublicKeySerParameter publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        if (this.params.getIds().length != publicKeyParameters.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector set length");
        }
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);
        Element beta = pairing.getZr().newRandomElement().getImmutable();

        this.sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(beta).getImmutable();
        this.C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
        this.C1 = publicKeyParameters.getG3().getImmutable();
        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (ids[i] != null){
                C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
            }
        }
        C1 = C1.powZn(beta).getImmutable();
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C2 = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new HIBBELLW16aCiphertextSerParameter(publicKeyParameter.getParameters(), C0, C1, C2);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new HIBBELLW16aHeaderSerParameter(publicKeyParameter.getParameters(), C0, C1)
        );
    }
}
