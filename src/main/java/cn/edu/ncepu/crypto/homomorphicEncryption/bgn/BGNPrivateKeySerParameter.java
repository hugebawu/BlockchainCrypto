package cn.edu.ncepu.crypto.homomorphicEncryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/21 10:06
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
 * @ClassName BGNPrivateKey
 * @Description This is a class for storing the private key (p) of BGN.
 * @Author Administrator
 * @Date 2020/12/21 10:06
 * @Version 1.0
 **/
public class BGNPrivateKeySerParameter extends PairingKeySerParameter {

//    private Pairing pairing;

    private transient BigInteger p;
    private final byte[] byteArrayP;

    private transient Element g;
    private final byte[] byteArrayG;

    public BGNPrivateKeySerParameter(PairingParameters pairingParameters, BigInteger p, Element g) {
        super(true, pairingParameters);
        this.p = p;
        this.byteArrayP = p.toByteArray();
        this.g = g.getImmutable();
        this.byteArrayG = g.toBytes();
    }

    public BigInteger getP() {
        return p;
    }

    public Element getG() {
        return g.getImmutable();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BGNPrivateKeySerParameter) {
            BGNPrivateKeySerParameter that = (BGNPrivateKeySerParameter) anObject;
            // Compare p
            if (!this.p.equals(that.p)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayP, that.byteArrayP)) {
                return false;
            }
            // Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
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
        this.p = new BigInteger(this.byteArrayP);
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
    }
}
