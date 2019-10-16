package cn.edu.ncepu.crypto.encryption.abe.cpabe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;


/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * CP-ABE secret key generation parameter.
 */
public class CPABESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] attributes;

    public CPABESecretKeyGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter, String[] attributes) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public String[] getAttributes() { return this.attributes; }
}