package cn.edu.buaa.crypto.encryption.ibbe.del07.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/8/23.
 *
 * Master Secret Key Parameters for Delerablée IBBE
 */
public class IBBEDel07MasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element gamma;
    private final byte[] byteArrayGamma;

    public IBBEDel07MasterSecretKeySerParameter(PairingParameters pairingParameters, Element g, Element gamma) {
        super(true, pairingParameters);
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.gamma = gamma.getImmutable();
        this.byteArrayGamma = this.gamma.toBytes();
    }

    public Element getG(){
        return this.g.duplicate();
    }

    public Element getGamma() { return this.gamma.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBBEDel07MasterSecretKeySerParameter) {
            IBBEDel07MasterSecretKeySerParameter that = (IBBEDel07MasterSecretKeySerParameter)anObject;
            //compare g
            if (!(PairingUtils.isEqualElement(this.g, that.getG()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //compare gamma
            if (!(PairingUtils.isEqualElement(this.gamma, that.getGamma()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGamma, that.byteArrayGamma)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.gamma = pairing.getZr().newElementFromBytes(this.byteArrayGamma).getImmutable();
    }
}
