package cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE ciphertext parameters.
 */
public class HIBBELLW16aCiphertextSerParameter extends HIBBELLW16aHeaderSerParameter {
    private transient Element C2;
    private final byte[] byteArrayC2;

    public HIBBELLW16aCiphertextSerParameter(PairingParameters pairingParameters, Element C0, Element C1, Element C2) {
        super(pairingParameters, C0, C1);

        this.C2 = C2.getImmutable();
        this.byteArrayC2 = this.C2.toBytes();
    }

    public Element getC2() { return this.C2.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16aCiphertextSerParameter) {
            HIBBELLW16aCiphertextSerParameter that = (HIBBELLW16aCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.C2, that.getC2())
                    && Arrays.equals(this.byteArrayC2, that.byteArrayC2)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C2 = pairing.getGT().newElementFromBytes(this.byteArrayC2).getImmutable();
    }
}