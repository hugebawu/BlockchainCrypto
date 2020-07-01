package cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog.serparams;

import java.math.BigInteger;

import cn.edu.ncepu.crypto.algebra.serparams.SecurePrimeSerParameter;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin secret key parameters
 */
public class DLogKR00bSecretKeySerParameter extends DLogKR00bKeySerParameter {
    private BigInteger x;

    public DLogKR00bSecretKeySerParameter(BigInteger x, SecurePrimeSerParameter params) {
        super(true, params);
        this.x = x;
    }

    public BigInteger getX() {
        return x;
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof DLogKR00bSecretKeySerParameter) {
            DLogKR00bSecretKeySerParameter that = (DLogKR00bSecretKeySerParameter)anOjbect;
            //Compare x
            if (!this.x.equals(that.getX())) {
                return false;
            }
            //Compare SecurePrimeSerParameter
            return this.getParameters().equals(that.getParameters());
        }
        return false;
    }
}