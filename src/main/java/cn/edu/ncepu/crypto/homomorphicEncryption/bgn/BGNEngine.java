package cn.edu.ncepu.crypto.homomorphicEncryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/17 10:17
 */

import cn.edu.ncepu.crypto.algebra.Engine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.math.BigInteger;

/**
 * @ClassName BGNEngine
 * @Description Engine for Boneh-Goh-Nissim cryptosystem defined and constructed in 2006
 * @Author Baiji Hu
 * @Date 2020/12/17 10:17
 * @Version 1.0
 **/
public class BGNEngine extends Engine {

    private static BGNEngine engine;
    private static final String SCHEME_NAME = "BGN 2006";
    private static final int T = 100; // The max range of message m
    private BGNPublicKey pubkey;
    private BGNPrivateKey prikey;

    public static BGNEngine getInstance() {
        if (null == engine) {
            // 满足的安全性可能有误，待定。
            engine = new BGNEngine(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA,
                    PredicateSecLevel.ANON);
        }
        return engine;
    }

    public BGNEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    /**
     * @description: This function returns the public key of BGN.
     * @return: The public key used to encrypt
     */
    public BGNPublicKey getPubkey() {
        return pubkey;
    }

    /**
     * @description: This function returns the private key of BGN
     * @return: the private key used to decrypt the data
     */
    public BGNPrivateKey getPrikey() {
        return prikey;
    }

    /*
     * @Description: This function is to encrypt the message m,
     * m in [0,1,2,...,T], T<<q.
     * @param m: The message
     * @param pubkey: The public key of BGN.
     * @return: Element: The ciphertext.
     * @throws: If the plaintext is not in [0,1,2,...,n], there is an exception.
     **/
    public Element encrypt(int m, BGNPublicKey pubkey) throws Exception {
        if (m > T) {
            throw new Exception("plaintext m should be in [0,1,2,...," + T + "]");
        }
        Pairing pairing = pubkey.getPairing();
        Element g = pubkey.getG();
        Element h = pubkey.getH();
        BigInteger r = pairing.getZr().newElement().toBigInteger();
        return g.pow(BigInteger.valueOf(m)).mul(h.pow(r)).getImmutable(); // g^m * h^r
    }

    /*
     * @description: This function is to decrypt the ciphertext with the public key and the private key.
     * @param c: The ciphertext.
     * @param pubkey: The public key of BGN
     * @param prikey: The private key of BGN
     * @return: int: The plaintext.
     * @throws: Exception If the plaintext is not in [0,1,2,...,n], there is an exception.
     **/
    public int decrypt(Element c, BGNPublicKey pubkey, BGNPrivateKey prikey) throws Exception {
        BigInteger p = prikey.getP();
        Element g = pubkey.getG();
        Element cp = c.pow(p).getImmutable();
        Element gp = g.pow(p).getImmutable();
        for (int i = 0; i <= T; i++) {
            if (gp.pow(BigInteger.valueOf(i)).isEqual(cp)) {
                return i;
            }
        }
        throw new Exception("plaintext m is not in [0,1,2,...," + T + "]");
    }

    public int decrypt_mul2(Element c, BGNPublicKey pubkey, BGNPrivateKey prikey) throws Exception {
        BigInteger p = prikey.getP();
        Element g = pubkey.getG();
        Element cp = c.pow(p).getImmutable();
        Pairing pairing = pubkey.getPairing();
        Element egg = pairing.pairing(g, g).pow(p).getImmutable();
        for (int i = 0; i <= T; i++) {
            if (egg.pow(BigInteger.valueOf(i)).isEqual(cp)) {
                return i;
            }
        }
        throw new Exception("plaintext m is not in [0,1,2,...," + T + "]");
    }

    /*
     * @description: The function supports the homomorphic addition with two ciphertext.
     * @param c1: The ciphertext.
     * @param c2: The ciphertext.
     * @return: Element The return value is c1*c2.
     * @throws:
     **/
    public Element add(Element c1, Element c2) {
        return c1.mul(c2).getImmutable();
    }

    /*
     * @description: The function supports the homomorphic multiplication with one ciphertext and one plaintext.
     * @param c1: The ciphertext.
     * @param m2: Element The plaintext.
     * @return: The return value is c^m.
     * @throws:
     **/
    public Element mul1(Element c1, int m2) {
        return c1.pow(BigInteger.valueOf(m2)).getImmutable();
    }

    /*
     * @description: The function supports the homomorphic multiplication with two ciphertext
     * @param c1: The ciphertext.
     * @param c2: The ciphertext.
     * @param pubkey: The public key of BNG
     * @return: Element The return value is e(c1,c2).
     * @throws:
     **/
    public Element mul2(Element c1, Element c2, BGNPublicKey pubkey) {
        Pairing pairing = pubkey.getPairing();
        return pairing.pairing(c1, c2).getImmutable();
    }

    /*
     * @description: The function supports the homomorphic self-blinding with one ciphertext and one random number.
     * @param c1: The ciphertext.
     * @param r2: A random number in Z_n.
     * @param pubkey:
     * @return: Element The return value is c1*h^r2.
     **/
    public Element selfBlind(Element c1, BigInteger r, BGNPublicKey pubkey) {
        Element h = pubkey.getH();
        return c1.mul(h.pow(r)).getImmutable();
    }
}
