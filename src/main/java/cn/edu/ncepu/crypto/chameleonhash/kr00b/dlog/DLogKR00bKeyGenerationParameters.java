package cn.edu.ncepu.crypto.chameleonhash.kr00b.dlog;

import cn.edu.ncepu.crypto.algebra.serparams.SecurePrimeSerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

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