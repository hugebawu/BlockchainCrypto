package cn.edu.ncepu.crypto.encryption.be.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * BE decapsulation generation parameter.
 */
public class BEDecapsulationGenerationParameter extends PairingDecryptionGenerationParameter {
    private int[] indexSet;

    public BEDecapsulationGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
                                              int[] indexSet, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.indexSet = PairingUtils.removeDuplicates(indexSet);
    }

    public int[] getIndexSet() { return this.indexSet; }
}
