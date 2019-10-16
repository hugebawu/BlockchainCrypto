package cn.edu.ncepu.crypto.encryption.ibe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Identity-Based Encryption decryption generation parameter.
 */
public class IBEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String id;

    public IBEDecryptionGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String id, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.id = id;
    }

    public String getId() {
        return this.id;
    }
}