package cn.edu.ncepu.crypto.signature.cl;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/7/2 21:05
 *//*
 * @ClassName CL04KeyPairGenerator
 * @Description Camenisch-Lysyanskaya-04 signature public key / secret key pair generator.
 * @Author Administrator
 * @Date 2021/7/2 21:05
 * @Version 1.0
 */
public class CL04SignKeyPairGenerator implements PairingKeyPairGenerator {
    private CL04SignKeyPairGenerationParameter param;
    final int messageSize;

    public CL04SignKeyPairGenerator(int messageSize) {
        this.messageSize = messageSize;
    }

    /**
     * intialise the key pair generator.
     *
     * @param param the parameters the key pair is to be initialized with.
     */
    @Override
    public void init(KeyGenerationParameters param) {
        this.param = (CL04SignKeyPairGenerationParameter) param;
    }

    /**
     * return an AsymmetricCipherKeyPair containing the generated keys.
     *
     * @return an AsymmetricCipherKeyPair containing the generated keys.
     */
    @Override
    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.param.getPairingParameters());
        // createSecretKey
        final Element g = pairing.getG1().newRandomElement().getImmutable();
        byte[] temp = g.toBytes();
        final Element gT = pairing.getGT().newRandomElement().getImmutable();
        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element[] z = IntStream.range(0, messageSize).mapToObj(i -> pairing.getZr().newRandomElement().getImmutable()).
                toArray(Element[]::new);
        CL04SignSecretPairingKeySerParameter secretKeyParameters = new CL04SignSecretPairingKeySerParameter(this.param.getPairingParameters(), g, x, y, z);
        // createPublicKey
        final Element X = g.powZn(x);
        final Element Y = g.powZn(y);
        final List<Element> Z = Arrays.stream(z).map(zi -> g.powZn(zi)).collect(Collectors.toList());
        final List<Element> Ztemp = Arrays.stream(z).map(zi -> g.powZn(zi)).collect(Collectors.toCollection(ArrayList::new));

        final List<Element> W = Arrays.stream(z).map(Y::powZn).collect(Collectors.toList());
        CL04SignPublicPairingKeySerParameter publicKeyParameters = new CL04SignPublicPairingKeySerParameter(this.param.getPairingParameters(), g, gT, X, Y, Z, W);
        return new PairingKeySerPair(publicKeyParameters, secretKeyParameters);
    }
}
