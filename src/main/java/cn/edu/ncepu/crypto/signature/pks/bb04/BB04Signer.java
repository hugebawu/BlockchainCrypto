package cn.edu.ncepu.crypto.signature.pks.bb04;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.signature.pks.PairingSigner;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/17.
 *
 * Boneh-Boyen short signatures.
 */
public class BB04Signer implements PairingSigner {
	/**
	 *
	 */
	private static final long serialVersionUID = -5144796190766545407L;

	public static final String SCHEME_NAME = "Boneh-Boyen-04 signature scheme";

	private PairingKeySerParameter pairingKeySerParameter;

	public BB04Signer() {

	}
	
	@Override
	public void init(boolean forSigning, CipherParameters param) {
		if (forSigning) {
			this.pairingKeySerParameter = (BB04SignSecretKeySerParameter) param;
		} else {
			this.pairingKeySerParameter = (BB04SignPublicKeySerParameter) param;
		}
	}

	@Override
	public void init(boolean forSigning, CipherParameters[] paramArray) {

	}

	public Element[] generateSignature(byte[] message) {
		PairingParameters params = this.pairingKeySerParameter.getParameters();
		Pairing pairing = PairingFactory.getPairing(params);
		BB04SignSecretKeySerParameter secretKeyParameters = (BB04SignSecretKeySerParameter) this.pairingKeySerParameter;
		Element x = secretKeyParameters.getX();
		Element y = secretKeyParameters.getY();
		Element g1 = secretKeyParameters.getPublicKeyParameters().getG1();

		Element r = pairing.getZr().newRandomElement().getImmutable();
		Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.Zr);
		Element sigma = g1.powZn(y.mulZn(r).add(m).add(x).invert()).getImmutable();

		return new Element[]{sigma, r};
	}

	@Override
	public Element[] batchGenerateSignature(byte[][] message) {
		return new Element[0];
	}

	public boolean verifySignature(byte[] message, Element... signature) {
		PairingParameters params = this.pairingKeySerParameter.getParameters();
		Pairing pairing = PairingFactory.getPairing(params);
		BB04SignPublicKeySerParameter publicKeyParameters = (BB04SignPublicKeySerParameter) this.pairingKeySerParameter;
		Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.Zr);
		Element g1 = publicKeyParameters.getG1();
		Element g2 = publicKeyParameters.getG2();
		Element u = publicKeyParameters.getU();
		Element v = publicKeyParameters.getV();

		Element sigma = signature[0];
		Element r = signature[1];

		Element temp1 = pairing.pairing(g1, g2);
		Element temp2 = pairing.pairing(sigma, u.mul(g2.powZn(m)).mul(v.powZn(r)));
		return PairingUtils.isEqualElement(temp1, temp2);
	}

	@Override
	public boolean batchVerifySignature(byte[][] messageArray, Element[] signatureArray) {
		return false;
	}

	public byte[] derEncode(Element[] signElements) throws IOException {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new DERPrintableString(Hex.toHexString(signElements[0].toBytes())));
		v.add(new DERPrintableString(Hex.toHexString(signElements[1].toBytes())));
		return new DERSequence(v).getEncoded(ASN1Encoding.DER);
	}

	@Override
	public byte[][] derBatchEncode(Element[] signElements) throws IOException {
		return new byte[0][];
	}

	public Element[] derDecode(byte[] encoding) throws IOException {
		ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
		PairingParameters params = this.pairingKeySerParameter.getParameters();
		Pairing pairing = PairingFactory.getPairing(params);

		return new Element[]{
				pairing.getG1().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(0)).getString())),
				pairing.getZr().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(1)).getString())),};
	}

	@Override
	public Element[] derBatchDecode(byte[][] encodingArray) throws IOException {
		return new Element[0];
	}

	public String getEngineName() {
		return SCHEME_NAME;
	}
}
