package cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bSecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE session key decapsulation generator.
 */
public class HIBBELLW16bDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private HIBBEDecryptionGenerationParameter params;
    private Element sessionKey;

    public void init(CipherParameters params) {
        this.params = (HIBBEDecryptionGenerationParameter)params;
    }

    private void verifyCiphertext() throws InvalidCipherTextException {
        HIBBELLW16bHeaderSerParameter headerParameter = (HIBBELLW16bHeaderSerParameter)this.params.getCiphertextParameter();
        Signer signer = this.params.getSigner();
        signer.init(false, headerParameter.getSignPublicKey());
        byte[] byteArrayC0 = headerParameter.getC0().toBytes();
        signer.update(byteArrayC0, 0, byteArrayC0.length);
        byte[] byteArrayC1 = headerParameter.getC1().toBytes();
        signer.update(byteArrayC1, 0, byteArrayC1.length);
        if (headerParameter instanceof HIBBELLW16bCiphertextSerParameter) {
            byte[] byteArrayC2 = ((HIBBELLW16bCiphertextSerParameter)headerParameter).getC2().toBytes();
            signer.update(byteArrayC2, 0, byteArrayC2.length);
        }
        if (!signer.verifySignature(headerParameter.getSignature())) {
            throw new InvalidCipherTextException("Invalid ciphertext.");
        }
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        HIBBELLW16bPublicKeySerParameter publicKeyParameters = (HIBBELLW16bPublicKeySerParameter)this.params.getPublicKeyParameter();
        HIBBELLW16bSecretKeySerParameter secretKeyParameters = (HIBBELLW16bSecretKeySerParameter)this.params.getSecretKeyParameter();
        HIBBELLW16bHeaderSerParameter ciphertextParameters = (HIBBELLW16bHeaderSerParameter)this.params.getCiphertextParameter();
        if (this.params.getIds().length != publicKeyParameters.getMaxUser()
                || secretKeyParameters.getIds().length != publicKeyParameters.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector / identity vector set length");
        }

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getIds(), PairingUtils.PairingGroupType.Zr);

        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (secretKeyParameters.getIdAt(i) != null &&
                    !secretKeyParameters.getElementIdAt(i).equals(elementIdsCT[i])){
                throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector set");
            }
        }

        Element a0 = secretKeyParameters.getA0().getImmutable();
        Element C0 = ciphertextParameters.getC0().getImmutable();
        Element C1 = ciphertextParameters.getC1().getImmutable();
        Element a1 = secretKeyParameters.getA1().getImmutable();

        //decapsulation
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(ciphertextParameters.getSignPublicKey());
            byte[] byteArraySignPublicKey = byteArrayOutputStream.toByteArray();
            objectOutputStream.close();
            byteArrayOutputStream.close();
            Element elementVk = PairingUtils.MapByteArrayToGroup(pairing, byteArraySignPublicKey, PairingUtils.PairingGroupType.Zr);

            for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
                if (secretKeyParameters.getIdAt(i) == null && params.getIdsAt(i) != null) {
                    a0 = a0.mul(secretKeyParameters.getBsAt(i).powZn(elementIdsCT[i])).getImmutable();
                }
            }
            a0 = a0.mul(secretKeyParameters.getBv().powZn(elementVk)).getImmutable();
            Element temp0 = pairing.pairing(C0, a0).getImmutable();
            Element temp1 = pairing.pairing(a1, C1).getImmutable();
            this.sessionKey = temp0.div(temp1).getImmutable();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        verifyCiphertext();
        computeDecapsulation();
        HIBBELLW16bCiphertextSerParameter ciphertextParameter = (HIBBELLW16bCiphertextSerParameter)this.params.getCiphertextParameter();
        return ciphertextParameter.getC2().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        verifyCiphertext();
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
