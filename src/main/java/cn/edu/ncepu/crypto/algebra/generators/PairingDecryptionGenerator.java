package cn.edu.ncepu.crypto.algebra.generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * interface that a pairing-based decryption generator should conform to.
 */
public interface PairingDecryptionGenerator {
	/**
	 * intialise the pairing-based decryption generator.
	 *
	 * @param params the parameters the decryption is to be initialised with.
	 */
	void init(CipherParameters params);

	/**
	 * return the message recovered from the ciphertext.
	 *
	 * @return the message recovered from the ciphertext.
	 */
	Element recoverMessage() throws InvalidCipherTextException;
}
