package cn.edu.ncepu.crypto.homomorphicEncryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/21 10:05
 */

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * @ClassName BGNPublicKey
 * @Description This is a class for storing the public key (n,G,GT,e,g,h) of BGN.
 * @Author Administrator
 * @Date 2020/12/21 10:05
 * @Version 1.0
 **/
public class BGNPublicKeySerParameter extends PairingKeySerParameter {
    private transient BigInteger n;
    private final byte[] byteArrayN;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element h;
    private final byte[] byteArrayH;

    public BGNPublicKeySerParameter(PairingParameters pairingParameters, BigInteger n, Element g, Element h) {
        super(false, pairingParameters);
        this.n = n;
        this.byteArrayN = this.n.toByteArray();
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.h = h.getImmutable();
        this.byteArrayH = this.h.toBytes();
    }

    public BigInteger getN() {
        return n;
    }

    public Element getG() {
        return g.getImmutable();
    }

    public Element getH() {
        return h.getImmutable();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BGNPublicKeySerParameter) {
            BGNPublicKeySerParameter that = (BGNPublicKeySerParameter) anObject;
            // Compare 
            if (!(this.n.equals(that.n))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayN, that.byteArrayN)) {
                return false;
            }
            // Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            // Compare h
            if (!PairingUtils.isEqualElement(this.h, that.h)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                return false;
            }
            // Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.n = new BigInteger(this.byteArrayN);
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
    }
}
