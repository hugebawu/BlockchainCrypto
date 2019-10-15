package cn.edu.buaa.crypto.encryption.re.llw16b.serparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aHeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE header parameter.
 */
public class RELLW16bHeaderSerParameter extends RELLW16aHeaderSerParameter {
    private final byte[] chameleonHash;
    private final byte[] r;

    private final AsymmetricKeySerParameter chameleonHashPublicKey;

    private transient Element C01;
    private final byte[] byteArrayC01;

    private transient Element C02;
    private final byte[] byteArrayC02;

    public RELLW16bHeaderSerParameter(
            PairingParameters pairingParameters,
            byte[] chameleonHash, byte[] r, AsymmetricKeySerParameter chameleonHashPublicKey,
            Element C01, Element C02,
            Element C0, Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s) {
        super(pairingParameters, C0, C1s, C2s, C3s);
        this.chameleonHash = chameleonHash;
        this.r = r;

        this.chameleonHashPublicKey = chameleonHashPublicKey;

        this.C01 = C01.getImmutable();
        this.byteArrayC01 = this.C01.toBytes();

        this.C02 = C02.getImmutable();
        this.byteArrayC02 = this.C02.toBytes();
    }

    public byte[] getChameleonHash() {
        return this.chameleonHash;
    }

    public byte[] getR() {
        return this.r;
    }

    public AsymmetricKeySerParameter getChameleonHashPublicKey() {
        return this.chameleonHashPublicKey;
    }

    public Element getC01() {
        return this.C01.duplicate();
    }

    public Element getC02() {
        return this.C02.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELLW16bHeaderSerParameter) {
            RELLW16bHeaderSerParameter that = (RELLW16bHeaderSerParameter) anObject;
            if (!PairingUtils.isEqualElement(this.C01, that.C01)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC01, that.byteArrayC01)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C02, that.C02)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC02, that.byteArrayC02)) {
                return false;
            }
            //Compare chameleon hash key
            if (!(this.chameleonHashPublicKey.equals(that.chameleonHashPublicKey))) {
                return false;
            }
            //Compare chameleon hash
            return Arrays.equals(this.r, that.r)
                    && Arrays.equals(this.chameleonHash, that.chameleonHash)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C01 = pairing.getG1().newElementFromBytes(this.byteArrayC01).getImmutable();
        this.C02 = pairing.getG1().newElementFromBytes(this.byteArrayC02).getImmutable();
    }
}
