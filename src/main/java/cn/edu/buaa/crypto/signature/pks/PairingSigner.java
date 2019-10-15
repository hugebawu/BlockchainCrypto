package cn.edu.buaa.crypto.signature.pks;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/17.
 *
 * Pairing-based signature scheme interface.
 */
public interface PairingSigner extends java.io.Serializable {
    String getEngineName();

    /**
     * Initialise the signer for signing or verification.
     *
     * @param forSigning true if for signing, false otherwise
     * @param param necessary parameters.
     */
    void init(boolean forSigning, CipherParameters param);

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    Element[] generateSignature(byte[] message);

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    boolean verifySignature(byte[] message, Element... signature);

    byte[] derEncode(Element[] signElements) throws IOException;

    Element[] derDecode(byte[] encoding) throws IOException;
}
