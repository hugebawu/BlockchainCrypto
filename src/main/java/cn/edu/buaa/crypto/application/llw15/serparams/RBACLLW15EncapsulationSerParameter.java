package cn.edu.buaa.crypto.application.llw15.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Liu-Liu-Wu role-based access control key encapsulation parameters.
 */
public class RBACLLW15EncapsulationSerParameter extends PairingCipherSerParameter {
    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element C1;
    private final byte[] byteArrayC1;

    public RBACLLW15EncapsulationSerParameter(PairingParameters pairingParameters, Element C0, Element C1) {
        super(pairingParameters);
        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1 = C1.getImmutable();
        this.byteArrayC1 = this.C1.toBytes();
    }

    public Element getC0() {
        return this.C0.duplicate();
    }

    public Element getC1() {
        return this.C1.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RBACLLW15EncapsulationSerParameter) {
            RBACLLW15EncapsulationSerParameter that = (RBACLLW15EncapsulationSerParameter) anObject;
            //Compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.getC0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //Compare C1
            if (!PairingUtils.isEqualElement(this.C1, that.getC1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC1, that.byteArrayC1)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1).getImmutable();
    }
}
