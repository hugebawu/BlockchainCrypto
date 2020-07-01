package cn.edu.ncepu.crypto.algebra.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Pairing-based serializable key parameters generator
 */
public interface PairingKeyParameterGenerator {

    void init(KeyGenerationParameters keyGenerationParameters);

    PairingKeySerParameter generateKey();
}
