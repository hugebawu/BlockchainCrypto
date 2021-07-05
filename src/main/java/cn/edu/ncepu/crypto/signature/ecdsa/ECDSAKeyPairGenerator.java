package cn.edu.ncepu.crypto.signature.ecdsa;

import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/4/25 19:56
 *//*
 * @ClassName ECDSAKeySerPairGenerator
 * @Description TODO
 * @Author Administrator
 * @Date 2021/4/25 19:56
 * @Version 1.0
 */
public class ECDSAKeyPairGenerator implements AsymmetricKeySerPairGenerator {
    private int KEYSIZE = 0;
    private SecureRandom SECURE_RANDOM = null;
    private final int KEYSIZE_MIN = 8;
    private final int KEYSIZE_DEFAULT = 32;
    private final int KEYSIZE_MAX = 3096;
    ECDSAKeyPairGenerationParameter param;

    @Override
    public void init(KeyGenerationParameters param) {
        this.param = (ECDSAKeyPairGenerationParameter) param;
        SECURE_RANDOM = param.getRandom();
        if (SECURE_RANDOM == null) {
            SECURE_RANDOM = new SecureRandom();
        }
        KEYSIZE = param.getStrength();
        if (KEYSIZE < KEYSIZE_MIN || KEYSIZE > KEYSIZE_MAX)
            this.KEYSIZE = KEYSIZE_DEFAULT;
    }

    @Override
    public AsymmetricKeySerPair generateKeyPair() {
        PairingParameters pairingParameters = this.param.getPairingParameters();
        BigInteger n = pairingParameters.getBigInteger("r");
        BigInteger q = pairingParameters.getBigInteger("q");
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element G = pairing.getG1().newRandomElement().getImmutable();
        Element d = pairing.getZr().newRandomElement().getImmutable();
        Element Q = G.powZn(d).getImmutable();
        AsymmetricKeySerParameter privateParam = new ECDSASecretKeySerParameter(d, G, pairingParameters);
        AsymmetricKeySerParameter publicParam = new ECDSAPublicKeySerParameter(Q, G, pairingParameters);
        return new AsymmetricKeySerPair(publicParam, privateParam);
    }
}
