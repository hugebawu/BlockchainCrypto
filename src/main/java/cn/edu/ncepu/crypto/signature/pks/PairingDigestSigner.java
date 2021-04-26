package cn.edu.ncepu.crypto.signature.pks;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/18.
 * <p>
 * Pairing-based digital signature.
 */
public class PairingDigestSigner implements Signer {
	private final Digest digest;
	private final PairingSigner pairingSigner;
	private boolean forSigning;

	public PairingDigestSigner(PairingSigner signer, Digest digest) {
		this.digest = digest;
		this.pairingSigner = signer;
	}

	@Override
	public void init(boolean forSigning, CipherParameters parameters) {
		this.forSigning = forSigning;
		PairingKeySerParameter k = (PairingKeySerParameter) parameters;
		if (forSigning && !k.isPrivate()) {
			throw new IllegalArgumentException("Signing Requires Private Key.");
		}

		if (!forSigning && k.isPrivate()) {
			throw new IllegalArgumentException("Verification Requires Public Key.");
		}

		reset();

		pairingSigner.init(forSigning, parameters);
	}

	public void init(boolean forSigning, CipherParameters[] parametersArray) {
		this.forSigning = forSigning;
		PairingKeySerParameter[] k = (PairingKeySerParameter[]) parametersArray;

		if (forSigning) {
			for (int i = 0; i < k.length; i++) {
				if (!k[i].isPrivate()) {
					throw new IllegalArgumentException("Batch Signing Requires Private Key.");
				}
			}
		}

		if (!forSigning) {
			for (int i = 0; i < k.length; i++) {
				if (k[i].isPrivate()) {
					throw new IllegalArgumentException("Batch Rerification Requires Public Key.");
				}
			}
		}
		reset();
		pairingSigner.init(forSigning, parametersArray);
	}

	/**
	 * update the internal digest with the byte b
	 */
	@Override
	public void update(byte input) {
		digest.update(input);
	}

	/**
	 * update the internal digest with the byte array in
	 */
	@Override
	public void update(byte[] input, int inOff, int length) {
		digest.update(input, inOff, length);
	}

	/**
	 * Generate a signature for the message we've been loaded with using
	 * the key we were initialised with.
	 */
	@Override
	public byte[] generateSignature() {
		if (!forSigning) {
			throw new IllegalStateException("PairingDigestSigner not initialised for signature generation.");
		}

		byte[] hash = new byte[digest.getDigestSize()];
		digest.doFinal(hash, 0);

		Element[] sig = pairingSigner.generateSignature(hash);

		try {
			return pairingSigner.derEncode(sig);
		} catch (IOException e) {
			throw new IllegalStateException("unable to encode signature");
		}
	}

	public byte[][] batchGenerateSignature(byte[][] msgArray) {
		if (!forSigning) {
			throw new IllegalStateException("PairingDigestSigner not initialised for signature generation.");
		}

		try {
			byte[][] hashArray = new byte[msgArray.length][];
			for (int i = 0; i < msgArray.length; i++) {
				digest.update(msgArray[i], 0, msgArray[i].length);
				hashArray[i] = new byte[digest.getDigestSize()];
				digest.doFinal(hashArray[i], 0);
			}
			Element[] sig = pairingSigner.batchGenerateSignature(hashArray);
			return pairingSigner.derBatchEncode(sig);
		} catch (IOException e) {
			throw new IllegalStateException("unable to encode signature");
		}
	}

	public boolean verifySignature(byte[] signature) {
		if (forSigning) {
			throw new IllegalStateException("PairingDigestSigner not initialised for verification");
		}

		byte[] hash = new byte[digest.getDigestSize()];
		digest.doFinal(hash, 0);

		try {
			Element[] sig = pairingSigner.derDecode(signature);
			return pairingSigner.verifySignature(hash, sig);
		} catch (IOException e) {
			return false;
		}
	}

	public boolean batchVerifySignature(byte[][] msgArray, byte[][] signatureArray) {
		if (forSigning) {
			throw new IllegalStateException("PairingDigestSigner not initialised for verification");
		}

		try {
			byte[][] hashArray = new byte[msgArray.length][];
			for (int i = 0; i < msgArray.length; i++) {
				digest.update(msgArray[i], 0, msgArray[i].length);
				hashArray[i] = new byte[digest.getDigestSize()];
				digest.doFinal(hashArray[i], 0);
			}
			Element[] sigArray = new Element[signatureArray.length];
			sigArray = pairingSigner.derBatchDecode(signatureArray);
			return pairingSigner.batchVerifySignature(hashArray, sigArray);
		} catch (IOException e) {
			return false;
		}
	}

	public void reset() {
		if (null != digest) {
			digest.reset();
		}
	}

}