package cn.edu.ncepu.crypto.signature.ecdsa;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 17, 2020 10:54:36 PM
 * @ClassName ECDSASigner
 * @Description: TODO(ecdsa signature scheme)
 */
public class ECDSASigner implements Signer {
	private final Digest digest;
	private final byte[] message;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private boolean forSigning;

	private Signature signature;

	private static Logger logger = LoggerFactory.getLogger(ECDSASigner.class);
	private static final String SCHEME_NAME = "Scott-Vanstone-1992 ecdsa signature scheme";
	private static final String SINGALGORITHM_STRING = "SHA256withECDSA";

	public ECDSASigner(Digest digest, byte[] message, PublicKey publicKey, PrivateKey privateKey) {
		this.digest = digest;
		this.message = message;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	@Override
	public void init(boolean forSigning, CipherParameters param) {

		this.forSigning = forSigning;

		try {
			this.signature = Signature.getInstance(SINGALGORITHM_STRING);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		}

		PairingKeySerParameter k = (PairingKeySerParameter) param;
		if (forSigning && !k.isPrivate()) {
			throw new IllegalArgumentException("Signing Requires Private Key.");
		}

		if (!forSigning && k.isPrivate()) {
			throw new IllegalArgumentException("Verification Requires Public Key.");
		}

		reset();
	}

	@Override
	public void update(byte b) {
		digest.update(b);
	}

	@Override
	public void update(byte[] in, int off, int len) {
		digest.update(in, off, len);
	}

	/**
	 * TODO(sign the message with private key)
	 * @param privateKey
	 * @param message
	 * @return signed message
	 * @return String
	 * @throws NoSuchAlgorithmException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] signECDSA(PrivateKey privateKey, byte[] message)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
		signature.initSign(privateKey);
		// when the message is big, it can be divided into blocks(e,g, 1KB one time)
		signature.update(message);
		/**
		 * 针对 SHA256withECDSA ，输出的是DER编码的签名数据，长度并非固定，但是是70到72字节，之所以会这样是因为，
		 * SHA256withECDSA 签名输出实际是两个32字节的大整数(r和s)，在转换成byte[]的时候，如果为负数，那么会添加前导位0，
		 * 如果当r和s都是正数，那么就是64个字节，都是负数，就是66字节。而DER编码还会包含类型以及长度字段，因此总长度就会到70到72字节。
		 * 一般情况下，传输DER编码的签名值没多大问题，但如果对数据量要求十分严格，例如在BLE上传输，可以提取出r和s再打包传输
		 */
		return signature.sign();
	}

	@Override
	public byte[] generateSignature() throws CryptoException, DataLengthException {
		if (!forSigning) {
			throw new IllegalStateException("ECDSASigner not initialised for signature generation.");
		}
		try {
			signature.initSign(this.privateKey);
			// when the message is big, it can be divided into blocks(e,g, 1KB one time)
			signature.update(this.message);
			/**
			 * 针对 SHA256withECDSA ，输出的是DER编码的签名数据，长度并非固定，但是是70到72字节，之所以会这样是因为，
			 * SHA256withECDSA 签名输出实际是两个32字节的大整数(r和s)，在转换成byte[]的时候，如果为负数，那么会添加前导位0，
			 * 如果当r和s都是正数，那么就是64个字节，都是负数，就是66字节。而DER编码还会包含类型以及长度字段，因此总长度就会到70到72字节。
			 * 一般情况下，传输DER编码的签名值没多大问题，但如果对数据量要求十分严格，例如在BLE上传输，可以提取出r和s再打包传输
			 */
			return signature.sign();
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
			throw new IllegalStateException("unable to encode signature: invalide Key");
		} catch (SignatureException e) {
			logger.error(e.getLocalizedMessage());
			throw new IllegalStateException("unable to encode signature: sinature exception");
		}
	}

	/**
	 * TODO(verify the ECDSA signature)
	 * @param publickey
	 * @param message
	 * @param singed
	 * @return ture or false
	 * @return boolean
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 * @throws DecoderException 
	 */
	public static boolean verifyECDSA(PublicKey publicKey, byte[] message, byte[] signed)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, DecoderException {
		Signature signature = Signature.getInstance(SINGALGORITHM_STRING);
		signature.initVerify(publicKey);
		signature.update(message);
		return signature.verify(signed);
	}

	@Override
	public boolean verifySignature(byte[] signed) {
		try {
			this.signature.initVerify(this.publicKey);
			signature.update(message);
			return this.signature.verify(signed);
		} catch (InvalidKeyException | SignatureException e) {
			logger.error(e.getLocalizedMessage());
			throw new IllegalStateException("unable to verify signature");
		}
	}

	@Override
	public void reset() {
		digest.reset();
	}

}
