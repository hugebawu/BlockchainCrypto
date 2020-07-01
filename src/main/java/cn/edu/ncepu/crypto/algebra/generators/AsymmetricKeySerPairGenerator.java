package cn.edu.ncepu.crypto.algebra.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerPair;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Asymmetric key pair generator.
 */
public interface AsymmetricKeySerPairGenerator {
    /**
     * intialise the key pair generator.
     *
     * @param param the parameters the key pair is to be initialised with.
     */
    void init(KeyGenerationParameters param);

    /**
     * return an AsymmetricCipherKeyPair containing the generated keys.
     *
     * @return an AsymmetricCipherKeyPair containing the generated keys.
     */
    AsymmetricKeySerPair generateKeyPair();
}
