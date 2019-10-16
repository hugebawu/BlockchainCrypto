package cn.edu.ncepu.crypto.encryption.hibe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * HIBE delegation generation parameter.
 */
public class HIBEDelegateGenerationParameter extends PairingKeyDelegationParameter {
    private String delegateId;

    public HIBEDelegateGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                           PairingKeySerParameter secretKeyParameter, String id) {
        super(publicKeyParameter, secretKeyParameter);
        this.delegateId = id;
    }

    public String getDelegateId() { return this.delegateId; }
}
