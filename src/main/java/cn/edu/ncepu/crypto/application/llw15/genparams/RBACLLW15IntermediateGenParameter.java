package cn.edu.ncepu.crypto.application.llw15.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu role-based access control intermediate generation parameters.
 */
public class RBACLLW15IntermediateGenParameter extends PairingEncapsulationGenerationParameter {
    public RBACLLW15IntermediateGenParameter(PairingKeySerParameter publicKeyParameter) {
        super(publicKeyParameter);
    }
}
