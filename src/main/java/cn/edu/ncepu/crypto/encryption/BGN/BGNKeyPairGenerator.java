package cn.edu.ncepu.crypto.encryption.BGN;
/**
 * @author Baiji Hu email: drbjhu@163.com
 * @date 2020/12/21 10:22
 */

import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
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
public class BGNKeyPairGenerator extends KeyPairGeneratorSpi {

    private int KEYSIZE = 0;
    private SecureRandom SECURE_RANDOM = null;
    private final int KEYSIZE_MIN = 8;
    private final int KEYSIZE_DEFAULT = 64;
    private final int KEYSIZE_MAX = 3096;

    /*
     * @description: Initialises <code>KeyPairGenerator</code> The key size is bound between 8
     * and 3096 bits. If its not within this rang, key size is set to default-64 bits.
     * @param keysize: the security parameters, which decides the bit length of each large prime (p and q)
     * @param random:
     * @return: void
     **/
    @Override
    public void initialize(int keysize, SecureRandom random) {
        SECURE_RANDOM = random;
        if (keysize < KEYSIZE_MIN || keysize > KEYSIZE_MAX)
            KEYSIZE = KEYSIZE_DEFAULT;
        else
            KEYSIZE = keysize;
    }

    /*
     * @description: This class is a simple holder for a key pair (a public key and a private
     * key). Constructs a key pair from the given public key and private key.
     * @return: java.security.KeyPair: - publicKey and privateKey
     **/
    @Override
    public KeyPair generateKeyPair() {
        if (SECURE_RANDOM == null) {
            SECURE_RANDOM = new SecureRandom();
        }
        // k is Type A1: symmetrical composite bilinear pairing.
        int numPrime = 2; // numPrime is the numbers of prime factor
        // Bilinear Pairing Parameters Generators
        PairingParameters typeA1Params = PairingUtils.genTypeA1PairParam(numPrime, KEYSIZE * 8);
        Pairing pairing = PairingFactory.getPairing(typeA1Params);
        BigInteger n = typeA1Params.getBigInteger("n");
        BigInteger p = typeA1Params.getBigInteger("n0");
        BigInteger q = typeA1Params.getBigInteger("n1");
        Field<Element> Field_G = pairing.getG1();
        Field<Element> Field_GT = pairing.getGT();
        Element g = Field_G.newRandomElement().getImmutable();
        Element u = Field_G.newRandomElement().getImmutable();
        Element h = u.pow(q).getImmutable();
        BGNPublicKey publicKey = new BGNPublicKey(n, Field_G, Field_GT, pairing, g, h);
        BGNPrivateKey privateKey = new BGNPrivateKey(p);
        return new KeyPair(publicKey, privateKey);
    }
}
