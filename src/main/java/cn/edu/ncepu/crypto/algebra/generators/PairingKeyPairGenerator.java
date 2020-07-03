package cn.edu.ncepu.crypto.algebra.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Asymmetric serializable key pair generator.
 */
public interface PairingKeyPairGenerator {
	/**
	 * intialise the key pair generator.
	 *
	 * @param param the parameters the key pair is to be initialized with.
	 */
	void init(KeyGenerationParameters param);

	/**
	 * return an AsymmetricCipherKeyPair containing the generated keys.
	 *
	 * @return an AsymmetricCipherKeyPair containing the generated keys.
	 */
	PairingKeySerPair generateKeyPair();
}
