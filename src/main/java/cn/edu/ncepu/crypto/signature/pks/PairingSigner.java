package cn.edu.ncepu.crypto.signature.pks;

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
	 * @param param      necessary parameters.
	 */
	void init(boolean forSigning, CipherParameters param);

	/**
	 * @param forSigning:
	 * @param paramArray:
	 * @description: Initialise the signer for batch signing or verification.
	 * @return: void
	 * @throws:
	 **/
	void init(boolean forSigning, CipherParameters[] paramArray);

	/**
	 * generate a signature for the message we've been loaded with using
	 * the key we were initialised with.
	 */
	Element[] generateSignature(byte[] message);

	Element[] batchGenerateSignature(byte[][] messageArray);

	/**
	 * return true if the internal state represents the signature described
	 * in the passed in array.
	 */
	boolean verifySignature(byte[] message, Element... signature);

	boolean batchVerifySignature(byte[][] messageArray, Element[] signatureArray);

	byte[] derEncode(Element[] signElements) throws IOException;

	byte[][] derBatchEncode(Element[] signElements) throws IOException;

	Element[] derDecode(byte[] encoding) throws IOException;

	Element[] derBatchDecode(byte[][] encodingArray) throws IOException;
}
