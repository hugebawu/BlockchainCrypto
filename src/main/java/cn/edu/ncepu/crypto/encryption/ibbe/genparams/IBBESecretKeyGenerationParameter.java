package cn.edu.ncepu.crypto.encryption.ibbe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE secret key generation parameter.
 */
public class IBBESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String id;

    public IBBESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter, String id) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

}

