package cn.edu.ncepu.crypto.signature.cl;

import cn.edu.ncepu.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/7/2 21:10
 *//*
 * @ClassName CL04KeyPairGenerationParameter
 * @Description TODO
 * @Author Administrator
 * @Date 2021/7/2 21:10
 * @Version 1.0
 */
public class CL04SignKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    public CL04SignKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}
