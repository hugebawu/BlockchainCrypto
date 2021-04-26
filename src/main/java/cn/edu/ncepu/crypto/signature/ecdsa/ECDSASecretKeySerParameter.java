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
 * @date 2021/4/25 19:51
 *//*
 * @ClassName ECDSASecretKeySerParameter
 * @Description serializable private key for ECDSA
 * @Author Administrator
 * @Date 2021/4/25 19:51
 * @Version 1.0
 */
public class ECDSASecretKeySerParameter extends AsymmetricKeySerParameter {
    private transient Element d;
    private final byte[] byteArrayD;
    private transient Element G;
    private final byte[] byteArrayG;
    private final PairingParameters parameters;

    public ECDSASecretKeySerParameter(Element d, Element G, PairingParameters pairingParameters) {
        super(true);
        this.d = d.getImmutable();
        this.byteArrayD = this.d.toBytes();
        this.G = G.getImmutable();
        this.byteArrayG = this.G.toBytes();
        this.parameters = pairingParameters;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof ECDSASecretKeySerParameter) {
            ECDSASecretKeySerParameter that = (ECDSASecretKeySerParameter) anObject;
            // Compare d
            if (!PairingUtils.isEqualElement(this.d, that.getD())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD, that.byteArrayD)) {
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
        this.d = pairing.getG1().newElementFromBytes(this.byteArrayD).getImmutable();
        this.G = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
    }

    public PairingParameters getParameters() {
        return parameters;
    }

    public Element getD() {
        return this.d.duplicate();
    }

    public Element getG() {
        return G;
    }
}
