package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * oyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles decryption generator.
 */
public class KPABEGPSW06bDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private KPABEDecryptionGenerationParameter params;
    private Element sessionKey;

    public void init(CipherParameters params) {
        this.params = (KPABEDecryptionGenerationParameter)params;
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        KPABEGPSW06bPublicKeySerParameter publicKeyParameter = (KPABEGPSW06bPublicKeySerParameter)this.params.getPublicKeyParameter();
        KPABEGPSW06bSecretKeySerParameter secretKeyParameter = (KPABEGPSW06bSecretKeySerParameter)this.params.getSecretKeyParameter();
        KPABEGPSW06bHeaderSerParameter ciphertextParameter = (KPABEGPSW06bHeaderSerParameter)this.params.getCiphertextParameter();
        AccessControlParameter accessControlParameter = secretKeyParameter.getAccessControlParameter();
        AccessControlEngine accessControlEngine = this.params.getAccessControlEngine();
        String[] attributes = this.params.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, attributes, accessControlParameter);
            this.sessionKey = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element D = secretKeyParameter.getDsAt(attribute);
                Element E = ciphertextParameter.getEsAt(attribute);
                Element R = secretKeyParameter.getRsAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                sessionKey = sessionKey.mul(pairing.pairing(D, ciphertextParameter.getE2()).div(pairing.pairing(R, E)).powZn(lambda)).getImmutable();
            }
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        KPABEGPSW06bCiphertextSerParameter ciphertextParameter = (KPABEGPSW06bCiphertextSerParameter)this.params.getCiphertextParameter();
        return ciphertextParameter.getE1().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
