package cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.serparams.SecurePrimeSerParameter;

/**
 * Created by Weiran Liu on 2016/10/20.
 *
 * Krawczyk-Rabin Chameleon hash public key / secret key generation parameters.
 */
public class DLogKR00bKeyGenerationParameters extends KeyGenerationParameters
{
    private SecurePrimeSerParameter params;

    public DLogKR00bKeyGenerationParameters(SecureRandom random, SecurePrimeSerParameter params)
    {
        super(random, params.getP().bitLength() - 1);

        this.params = params;
    }

    public SecurePrimeSerParameter getParameters()
    {
        return params;
    }
}