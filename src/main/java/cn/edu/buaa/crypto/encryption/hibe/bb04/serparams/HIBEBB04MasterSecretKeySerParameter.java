package cn.edu.buaa.crypto.encryption.hibe.bb04.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Master Secret Key Parameters for Boneh-Boyen HIBE.
 */
public class HIBEBB04MasterSecretKeySerParameter extends PairingKeySerParameter {

    private transient Element g2Alpha;
    private final byte[] byteArrayG2Alpha;

    public HIBEBB04MasterSecretKeySerParameter(PairingParameters pairingParameters, Element g2Alpha) {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
        this.byteArrayG2Alpha = this.g2Alpha.toBytes();
    }

    public Element getG2Alpha(){
        return this.g2Alpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04MasterSecretKeySerParameter) {
            HIBEBB04MasterSecretKeySerParameter that = (HIBEBB04MasterSecretKeySerParameter)anObject;
            if (!(PairingUtils.isEqualElement(this.g2Alpha, that.getG2Alpha()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2Alpha, that.byteArrayG2Alpha)) {
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
        this.g2Alpha = pairing.getG1().newElementFromBytes(this.byteArrayG2Alpha).getImmutable();
    }
}
