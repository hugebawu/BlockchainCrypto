package cn.edu.ncepu.crypto.encryption.BGN;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/21 10:05
 */

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * @ClassName BGNPublicKey
 * @Description This is a class for storing the public key (n,G,GT,e,g,h) of BGN.
 * @Author Administrator
 * @Date 2020/12/21 10:05
 * @Version 1.0
 **/
public class BGNPublicKey implements PublicKey {
    private BigInteger n;
    private Field<Element> Field_G, Field_GT;
    private Pairing pairing;
    private Element g, h;

    public BGNPublicKey(BigInteger n, Field<Element> G, Field<Element> GT,
                        Pairing pairing, Element g, Element h) {
        this.n = n;
        this.Field_G = G;
        this.Field_GT = GT;
        this.pairing = pairing;
        this.g = g;
        this.h = h;
    }

    public BigInteger getN() {
        return n;
    }

    public Field<Element> getField_G() {
        return Field_G;
    }

    public Field<Element> getField_GT() {
        return Field_GT;
    }

    public Pairing getPairing() {
        return pairing;
    }

    public Element getG() {
        return g;
    }

    public Element getH() {
        return h;
    }

    /*
     * @description: Returns the standard algorithm name for this key.
     * @return: java.lang.String
     **/
    @Override
    public String getAlgorithm() {
        return "Boneh-Goh-Nissim";
    }

    /*
     * @description: Returns the name of the primary encoding format of this key, or null if
     * this key does not support encoding.
     * @return: java.lang.String
     * @throws:
     **/
    @Override
    public String getFormat() {
        return "NONE";
    }

    /*
     * @description: Returns the key in its primary encoding format, or null if this key does
     * not support encoding.

     * @return: java.lang.String
     **/
    public byte[] getEncoded() {
        return null;
    }
}
