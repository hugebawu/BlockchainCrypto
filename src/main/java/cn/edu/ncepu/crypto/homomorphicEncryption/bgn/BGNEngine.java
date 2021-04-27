package cn.edu.ncepu.crypto.homomorphicEncryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/17 10:17
 */

import cn.edu.ncepu.crypto.algebra.Engine;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;

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
    private static final int M = 100; // The max range of message m

    public BGNEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    public static BGNEngine getInstance() {
        if (null == engine) {
            // 满足的安全性可能有误，待定。
            engine = new BGNEngine(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA,
                    PredicateSecLevel.ANON);
        }
        return engine;
    }

    public PairingKeySerPair keyGen(PairingParameters pairingParameters) throws InvalidAlgorithmParameterException {
        BGNKeyPairGenerator kpg = new BGNKeyPairGenerator(pairingParameters);
        kpg.init(new KeyGenerationParameters(null, 32));
        PairingKeySerPair keyPair = kpg.generateKeyPair();
        return keyPair;
    }

    /*
     * @Description: This function is to encrypt the message m,
     * m in [0,1,2,...,T], T<<q.
     * @param m: The message
     * @param pubkey: The public key of BGN.
     * @return: Element: The ciphertext.
     * @throws: If the plaintext is not in [0,1,2,...,n], there is an exception.
     **/
    public byte[] encrypt(int m, BGNPublicKeySerParameter pubkey) throws Exception {
        if (m > M) {
            throw new Exception("plaintext m should be in [0,1,2,...," + M + "]");
        }
        Element g = pubkey.getG();
        Element h = pubkey.getH();
        Pairing pairing = PairingFactory.getPairing(pubkey.getParameters());
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element c = g.pow(BigInteger.valueOf(m)).mul(h.powZn(r)).getImmutable(); // g^m * h^r
        return this.derEncode(c);
    }

    /*
     * @description: This function is to decrypt the ciphertext with the public key and the private key.
     * @param c: The ciphertext.
     * @param pubkey: The public key of BGN
     * @param prikey: The private key of BGN
     * @return: int: The plaintext.
     * @throws: Exception If the plaintext is not in [0,1,2,...,n], there is an exception.
     **/
    public int decrypt(byte[] byteArray, BGNPrivateKeySerParameter prikey) throws Exception {
        Element c = this.derDecode(byteArray, prikey.getParameters());
        BigInteger p = prikey.getP();
        Element g = prikey.getG();
        Element cp = c.pow(p).getImmutable();
        Element gp = g.pow(p).getImmutable();
        Pairing pairing = PairingFactory.getPairing(prikey.getParameters());
        for (int i = 0; i <= M; i++) {
            if (gp.powZn(pairing.getZr().newElement(i)).isEqual(cp)) {
                return i;
            }
        }
        throw new Exception("plaintext m is not in [0,1,2,...," + M + "]");
    }

    public int decrypt_mul2(Element c, BGNPrivateKeySerParameter prikey) throws Exception {
        BigInteger p = prikey.getP();
        Element g = prikey.getG();
        Element cp = c.pow(p).getImmutable();
        Pairing pairing = PairingFactory.getPairing(prikey.getParameters());
        Element egg = (pairing.pairing(g, g).pow(p)).getImmutable();
        for (int i = 0; i <= M; i++) {
            if (egg.powZn(pairing.getZr().newElement(i)).isEqual(cp)) {
                return i;
            }
        }
        throw new Exception("plaintext m is not in [0,1,2,...," + M + "]");
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
    public Element mul1(Element c1, int m2, BGNPublicKeySerParameter pubkey) {
        Pairing pairing = PairingFactory.getPairing(pubkey.getParameters());
        return c1.powZn(pairing.getZr().newElement(m2)).getImmutable();
    }

    /*
     * @description: The function supports the homomorphic multiplication with two ciphertext
     * @param c1: The ciphertext.
     * @param c2: The ciphertext.
     * @param pubkey: The public key of BNG
     * @return: Element The return value is e(c1,c2).
     * @throws:
     **/
    public Element mul2(Element c1, Element c2, BGNPublicKeySerParameter pubkey) {
        Pairing pairing = PairingFactory.getPairing(pubkey.getParameters());
        return pairing.pairing(c1, c2).getImmutable();
    }

    /*
     * @description: The function supports the homomorphic self-blinding with one ciphertext and one random number.
     * @param c1: The ciphertext.
     * @param r2: A random number in Z_n.
     * @param pubkey:
     * @return: Element The return value is c1*h^r2.
     **/
    public Element selfBlind(Element c1, BGNPublicKeySerParameter pubkey) {
        Pairing pairing = PairingFactory.getPairing(pubkey.getParameters());
        BigInteger r = pairing.getZr().newRandomElement().toBigInteger();
        Element h = pubkey.getH();
        return c1.mul(h.pow(r)).getImmutable();
    }

    /**
     * @param signElement:
     * @description: encode curve element into the compressed format
     * @return: byte[]
     * @throws:
     **/
    public byte[] derEncode(Element signElement) throws IOException {
        return ((CurveElement<?, ?>) signElement).toBytesCompressed();
    }

    /**
     * @param encoding:
     * @description: decode byte compressed byteArray element into curveElement
     * @return: it.unisa.dia.gas.jpbc.Element[]
     * @throws:
     **/
    public Element derDecode(byte[] encoding, PairingParameters pairingParameters) throws IOException {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element curveElement = pairing.getG1().newZeroElement();
        ((CurveElement<?, ?>) curveElement).setFromBytesCompressed(encoding);
        return curveElement;
    }
}
