package cn.edu.buaa.crypto.algebra.generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 15-9-30.
 * interface that a pairing KEM decryption generator should conform to.
 */
public interface PairingDecapsulationGenerator {
    /**
     * intialise the KEM decryption generator.
     *
     * @param params the parameters the decapsulation is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * return the session key recovered from the ciphertext.
     *
     * @return the session key recovered from the ciphertext.
     */
    byte[] recoverKey() throws InvalidCipherTextException;
}
