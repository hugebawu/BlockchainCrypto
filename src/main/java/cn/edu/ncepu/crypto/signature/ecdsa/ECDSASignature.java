package cn.edu.ncepu.crypto.signature.ecdsa;

import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.Serializable;
import java.util.Arrays;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/4/25 22:18
 */
/*
 * @ClassName ECDSASignature
 * @Description signature result (r,s) of ECDSA
 * @Author Administrator
 * @Date 2021/4/25 22:18
 * @Version 1.0
 */
public class ECDSASignature implements Serializable {
    private transient Element r;
    private final byte[] byteArrayR;
    private transient Element s;
    private final byte[] byteArrayS;
    private final PairingParameters parameters;

    public ECDSASignature(Element r, Element s, PairingParameters pairingParameters) {
        this.r = r.getImmutable();
        this.s = s.getImmutable();
        this.byteArrayR = r.toBytes();
        this.byteArrayS = s.toBytes();
        this.parameters = pairingParameters;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof ECDSASignature) {
            ECDSASignature that = (ECDSASignature) anObject;
            // Compare r
            if (!PairingUtils.isEqualElement(this.r, that.getR())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayR, that.byteArrayR)) {
                return false;
            }
            // Compare s
            if (!PairingUtils.isEqualElement(this.s, that.getS())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayS, that.byteArrayS)) {
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
        this.r = pairing.getZr().newElementFromBytes(this.byteArrayR).getImmutable();
        this.s = pairing.getZr().newElementFromBytes(this.byteArrayS).getImmutable();
    }

    public Element getR() {
        return r;
    }

    public Element getS() {
        return s;
    }
}
