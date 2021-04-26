package cn.edu.ncepu.crypto.signature.ecdsa;

import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/4/25 19:46
 *//*
 * @ClassName ECDSAPublicKeySerParameter
 * @Description serializable public key of ECDSA
 * @Author Administrator
 * @Date 2021/4/25 19:46
 * @Version 1.0
 */
public class ECDSAPublicKeySerParameter extends AsymmetricKeySerParameter {
    private transient Element Q;
    private final byte[] byteArrayQ;
    private transient Element G;
    private final byte[] byteArrayG;
    private final PairingParameters parameters;

    public ECDSAPublicKeySerParameter(Element Q, Element G, PairingParameters pairingParameters) {
        super(false);
        this.Q = Q.getImmutable();
        this.byteArrayQ = this.Q.toBytes();
        this.G = G.getImmutable();
        this.byteArrayG = this.G.toBytes();
        this.parameters = pairingParameters;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof ECDSAPublicKeySerParameter) {
            ECDSAPublicKeySerParameter that = (ECDSAPublicKeySerParameter) anObject;
            // Compare g
            if (!PairingUtils.isEqualElement(this.Q, that.getQ())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayQ, that.byteArrayQ)) {
                return false;
            }
            // Compare G
            if (!PairingUtils.isEqualElement(this.G, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            // Compare Pairing Parameters
            return this.parameters.toString().equals(that.parameters.toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.parameters);
        this.Q = pairing.getG1().newElementFromBytes(this.byteArrayQ).getImmutable();
        this.G = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
    }

    public Element getQ() {
        return this.Q.duplicate();
    }

    public Element getG() {
        return G;
    }

    public PairingParameters getParameters() {
        return parameters;
    }
}
