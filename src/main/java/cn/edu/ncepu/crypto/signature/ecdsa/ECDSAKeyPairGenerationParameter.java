package cn.edu.ncepu.crypto.signature.ecdsa;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/4/25 20:38
 *//*
 * @ClassName ECDSAKeyPairGenerationParameter
 * @Description TODO
 * @Author Administrator
 * @Date 2021/4/25 20:38
 * @Version 1.0
 */
public class ECDSAKeyPairGenerationParameter extends KeyGenerationParameters {
    private final PairingParameters pairingParameters;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random            the random byte source.
     * @param strength          the size, in bits, of the keys we want to produce.
     * @param pairingParameters
     */
    public ECDSAKeyPairGenerationParameter(SecureRandom random, int strength, PairingParameters pairingParameters) {
        super(random, strength);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }
}
