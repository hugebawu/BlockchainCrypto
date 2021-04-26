package cn.edu.ncepu.crypto.signature.ecdsa;

import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.ImmutableCurveElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @Copyright : Copyright (c) 2020-2021
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 17, 2020 10:54:36 PM
 * @ClassName ECDSASigner
 * @Description: (ecdsa signature scheme)
 */
@SuppressWarnings("unused")
public class ECDSASigner implements Signer {
	private static final Logger logger = LoggerFactory.getLogger(ECDSASigner.class);
	public static final String SCHEME_NAME = "Don Johnson, Alfred Menezes, Scott-Vanstone-2001";
	private final Digest digest;
	private boolean forSigning;
	private AsymmetricKeySerParameter asymmetricKeySerParameter;

	public ECDSASigner(Digest digest) {
		this.digest = digest;
	}

	@Override
	public void init(boolean forSigning, CipherParameters param) {
		this.forSigning = forSigning;
		AsymmetricKeySerParameter k = (AsymmetricKeySerParameter) param;
		if (forSigning && !k.isPrivate()) {
			throw new IllegalArgumentException("Signing Requires Private Key.");
		}
		if (!forSigning && k.isPrivate()) {
			throw new IllegalArgumentException("Verification Requires Public Key.");
		}
		if (forSigning) {
			this.asymmetricKeySerParameter = (ECDSASecretKeySerParameter) param;
		} else {
			this.asymmetricKeySerParameter = (ECDSAPublicKeySerParameter) param;
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

	@Override
	public byte[] generateSignature() throws CryptoException, DataLengthException {
		/**
		 * 针对 SHA256withECDSA ，输出的是DER编码的签名数据，长度并非固定，但是是70到72字节，之所以会这样是因为，
		 * SHA256withECDSA 签名输出实际是两个32字节的大整数(r和s)，在转换成byte[]的时候，如果为负数，那么会添加前导位0，
		 * 如果当r和s都是正数，那么就是64个字节，都是负数，就是66字节。而DER编码还会包含类型以及长度字段，因此总长度就会到70到72字节。
		 * 一般情况下，传输DER编码的签名值没多大问题，但如果对数据量要求十分严格，例如在BLE上传输，可以提取出r和s再打包传输
		 */
		if (!forSigning) {
			throw new IllegalStateException("ECDSA Signer not initialised for signature generation.");
		}
		try {
			// generate hash digest
			// when the message is big, it can be divided into blocks(e,g, 1KB one time)
			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);
			ECDSASecretKeySerParameter secretKeySerParameter = (ECDSASecretKeySerParameter) asymmetricKeySerParameter;
			Pairing pairing = PairingFactory.getPairing(secretKeySerParameter.getParameters());
			Element k = pairing.getZr().newRandomElement().getImmutable();
			ImmutableCurveElement Gk = (ImmutableCurveElement) (secretKeySerParameter.getG().powZn(k));
			Element x1 = Gk.getX();
			Element r = pairing.getZr().newElement(x1).getImmutable();
			Element e = pairing.getZr().newElement(new BigInteger(hash)).getImmutable();
			Element d = secretKeySerParameter.getD();
			Element s = k.invert().mul(e.add(d.mul(r)));
			ECDSASignature ecdsaSignature = new ECDSASignature(r, s, secretKeySerParameter.getParameters());
			return CommonUtils.SerObject(ecdsaSignature);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param signed:
	 * @description: verify the ECDSA signature
	 * @return: boolean
	 * @throws:
	 **/
	@Override
	public boolean verifySignature(byte[] signed) {
		if (forSigning) {
			throw new IllegalStateException("ECDSA Signer not initialised for signature verify.");
		}
		try {
			// generate hash digest
			// when the message is big, it can be divided into blocks(e,g, 1KB one time)
			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);
			ECDSAPublicKeySerParameter publicKeySerParameter = (ECDSAPublicKeySerParameter) asymmetricKeySerParameter;
			Pairing pairing = PairingFactory.getPairing(publicKeySerParameter.getParameters());
			ECDSASignature ecdsaSignature = (ECDSASignature) CommonUtils.deserObject(signed);
			Element r = ecdsaSignature.getR();
			Element s = ecdsaSignature.getS();
			Element e = pairing.getZr().newElement(new BigInteger(hash)).getImmutable();
			Element w = s.invert();
			Element u1 = e.mul(w);
			Element u2 = r.mul(w);
			ImmutableCurveElement X = (ImmutableCurveElement) (publicKeySerParameter.getG().powZn(u1).add(publicKeySerParameter.getQ().powZn(u2)));
			Element x2 = X.getX();
			Element v = pairing.getZr().newElement(x2).getImmutable();
			return v.isEqual(r);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public void reset() {
		digest.reset();
	}
}
