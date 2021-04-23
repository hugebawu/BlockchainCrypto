package cn.edu.ncepu.crypto.homomorphicEncryption.bgn;
/**
 * @author Baiji Hu email: drbjhu@163.com
 * @date 2020/12/21 10:22
 */

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @ClassName BGNKeyPairGenerator
 * @Description: The BGNKeyPairGenerator class is used to
 * generate pairs of public and private keys. Key pair generators are constructed using the
 * getInstance factory methods (static methods that return instances of a given class).
 * <p>
 * A Key pair generator for a particular algorithm creates a public/private key
 * pair that can be used with this algorithm.
 * <p>
 * There are two ways to generate a key pair: in an algorithm-independent manner, and in an
 * algorithm-specific manner. The only difference between the two is the initialization of the object.
 * <p>
 * @Author Administrator
 * @Date 2020/12/21 10:22 @Version 1.0
 */
public class BGNKeyPairGenerator implements PairingKeyPairGenerator {

    private int keysize = 0;
    private SecureRandom SECURE_RANDOM = null;
    private final int KEYSIZE_MIN = 8;
    private final int KEYSIZE_DEFAULT = 32;
    private final int KEYSIZE_MAX = 3096;
    private final PairingParameters typeA1Params;

    public BGNKeyPairGenerator(PairingParameters typeA1Params) {
        this.typeA1Params = typeA1Params;
    }

    @Override
    public void init(KeyGenerationParameters param) {
        SECURE_RANDOM = param.getRandom();
        keysize = param.getStrength();
        if (keysize < KEYSIZE_MIN || keysize > KEYSIZE_MAX)
            this.keysize = KEYSIZE_DEFAULT;

    }

    /*
     * @description: This class is a simple holder for a key pair (a public key and a private
     * key). Constructs a key pair from the given public key and private key.
     * @return: java.security.KeyPair: - publicKey and privateKey
     **/
    @Override
    public PairingKeySerPair generateKeyPair() {
        if (SECURE_RANDOM == null) {
            SECURE_RANDOM = new SecureRandom();
        }
        Pairing pairing = PairingFactory.getPairing(typeA1Params);
        BigInteger n = typeA1Params.getBigInteger("n");
        BigInteger p = typeA1Params.getBigInteger("n0");
        BigInteger q = typeA1Params.getBigInteger("n1");

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element u = pairing.getG1().newRandomElement().getImmutable();

        Element h = u.pow(q).getImmutable();
        BGNPublicKeySerParameter publicKey = new BGNPublicKeySerParameter(typeA1Params, n, g, h);
        BGNPrivateKeySerParameter privateKey = new BGNPrivateKeySerParameter(typeA1Params, p, g);
        return new PairingKeySerPair(publicKey, privateKey);
    }
}
