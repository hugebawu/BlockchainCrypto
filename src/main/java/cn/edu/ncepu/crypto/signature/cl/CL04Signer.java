package cn.edu.ncepu.crypto.signature.cl;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
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
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/7/2 20:20
 *//*
 * @ClassName CLSigner
 * @Description Implement of CL04-"Signature schemes and anonymous credentials from bilinear maps"
 * @Author Administrator
 * @Date 2021/7/2 20:20
 * @Version 1.0
 */
public class CL04Signer implements Signer {
  public static final String SCHEME_NAME = "Camenisch-Lysyanskaya-04 signature scheme";
  private final Digest digest;
  private boolean forSigning;
  private PairingKeySerParameter pairingKeySerParameter;

  private List<Element> messages;
  private Element commitment;

  public CL04Signer(Digest digest) {
    this.digest = digest;
  }

  public void setMessages(List<Element> messages) {
    this.messages = messages;
  }

  public void setCommitment(Element commitment) {
    this.commitment = commitment;
  }

  /**
   * Initialise the signer for signing or verification.
   *
   * @param forSigning true if for signing, false otherwise
   * @param param      necessary parameters.
   */
  @Override
  public void init(boolean forSigning, CipherParameters param) {
    this.forSigning = forSigning;
    PairingKeySerParameter pairingKeySerParameter = (PairingKeySerParameter) param;
    if (forSigning && !pairingKeySerParameter.isPrivate()) {
      throw new IllegalArgumentException("Signature Requires Private Key.");
    }
    if (!forSigning && pairingKeySerParameter.isPrivate()) {
      throw new IllegalArgumentException("Verification Requires Public Key.");
    }
    if (forSigning) {
      this.pairingKeySerParameter = (CL04SignSecretPairingKeySerParameter) param;
    } else {
      this.pairingKeySerParameter = (CL04SignPublicPairingKeySerParameter) param;
    }
    reset();
  }

  /**
   * update the internal digest with the byte b
   *
   * @param b
   */
  @Override
  public void update(byte b) {
    digest.update(b);
  }

  /**
   * update the internal digest with the byte array in
   *
   * @param in
   * @param off
   * @param len
   */
  @Override
  public void update(byte[] in, int off, int len) {
    digest.update(in, off, len);
  }

  /**
   * generate a signature for the message we've been loaded with using
   * the key we were initialised with.
   */
  @Override
  public byte[] generateSignature() throws CryptoException, DataLengthException {
    if (!forSigning) {
      throw new IllegalStateException("CL04 Signer not initialised for signature generation.");
    }

    try {
      CL04SignSecretPairingKeySerParameter sk = (CL04SignSecretPairingKeySerParameter) pairingKeySerParameter;
      Pairing pairing = PairingFactory.getPairing(sk.getParameters());
      final Element alpha = pairing.getZr().newRandomElement().getImmutable();
      final Element a = sk.getG().powZn(alpha);
      final List<Element> A = sk.getZ().stream().map(a::powZn).collect(Collectors.toCollection(ArrayList::new));
      final Element b = a.powZn(sk.getY()).getImmutable();
      final List<Element> B = A.stream().map(Ai -> Ai.powZn(sk.getY())).collect(Collectors.toCollection(ArrayList::new));
      final Element xTimesY = alpha.mul(sk.getX().mul(sk.getY()));
      final Element c = a.powZn(sk.getX()).mul(commitment.powZn(xTimesY)).getImmutable();

      Element[] signElements = new Element[3 + 2 * messages.size()];
      signElements[0] = a;
      signElements[1] = b;
      signElements[2] = c;
      for (int i = 0; i < messages.size(); i++) {
        signElements[3 + i] = A.get(i);
        signElements[3 + messages.size() + i] = B.get(i);
      }
      return derEncode(signElements);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  /**
   * return true if the internal state represents the signature described
   * in the passed in array.
   *
   * @param signature
   */
  @Override
  public boolean verifySignature(byte[] signature) {
    try {
      Element[] sig = derDecode(signature);
      CL04SignPublicPairingKeySerParameter pk = (CL04SignPublicPairingKeySerParameter) pairingKeySerParameter;
      Pairing pairing = PairingFactory.getPairing(pairingKeySerParameter.getParameters());
      Element a = sig[0];
      Element b = sig[1];
      Element c = sig[2];
      List<Element> A = IntStream.range(3, 3 + messages.size()).mapToObj(i -> sig[i]).collect(Collectors.toList());
      List<Element> B = IntStream.range(3 + messages.size(), 3 + 2 * messages.size()).mapToObj(i -> sig[i]).collect(Collectors.toList());
      return aFormedCorrectly(pairing, a, A, pk) && bFormedCorrectly(pairing, a, b, A, B, pk) && cFormedCorrectly(pairing, a, b, c, B, pk);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return false;

  }

  /**
   * reset the internal state
   */
  @Override
  public void reset() {
    digest.reset();
  }

  /**
   * @description: generate a commitment g^m(0)XPI(Z(j)^m(j))
   * @param: messages
   * @return: it.unisa.dia.gas.jpbc.Element
   * @throws:
   **/
  public Element generateCommit(final List<Element> messages) {
    CL04SignPublicPairingKeySerParameter pk = (CL04SignPublicPairingKeySerParameter) pairingKeySerParameter;
    if (messages.size() != pk.getZ().size()) {
      throw new IllegalStateException("Public key should be generated with the correct message size");
    }
    Element commitment = pk.getG().powZn(messages.get(0));
    for (int i = 1; i < messages.size(); i++) {
      commitment = commitment.mul(pk.getZ().get(i).powZn(messages.get(i)));
    }
    return commitment.getImmutable();
  }

  private byte[] derEncode(Element[] signElements) throws IOException {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (int i = 0; i < signElements.length; i++) {
      v.add(new DERPrintableString(Hex.toHexString(signElements[i].toBytes())));
    }
    return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    /*byte[][] encodingArray = IntStream.range(0, signElements.length).mapToObj(i -> ((CurveElement<?, ?>) signElements[i]).toBytesCompressed()).toArray(byte[][]::new);
    return encodingArray;*/
  }

  private Element[] derDecode(byte[] encoding) throws IOException {
    ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
    PairingParameters params = this.pairingKeySerParameter.getParameters();
    Pairing pairing = PairingFactory.getPairing(params);
    Element[] signElements = new Element[3 + 2 * messages.size()];
    for (int i = 0; i < signElements.length; i++) {
      signElements[i] = pairing.getG1().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(i)).getString())).getImmutable();
    }
    return signElements;
    /*PairingParameters params = this.pairingKeySerParameter.getParameters();
    Pairing pairing = PairingFactory.getPairing(params);
    Element[] signatures = new Element[encodingArray.length];
    Element[] signElements = IntStream.range(0, encodingArray.length).mapToObj(i -> ((CurveElement<?, ?>) signatures[i]).setFromBytesCompressed(encodingArray[i])).toArray(Element[]::new);
    return signElements;*/
  }

  private boolean aFormedCorrectly(Pairing pairing, Element a, List<Element> A, CL04SignPublicPairingKeySerParameter pk) {
    for (int i = 0; i < A.size(); i++) {
      if (!pairing.pairing(a, pk.getZ().get(i)).isEqual(pairing.pairing(pk.getG(), A.get(i)))) {
        return false;
      }
    }
    return true;
  }

  private boolean bFormedCorrectly(Pairing pairing, Element a, Element b, List<Element> A, List<Element> B, CL04SignPublicPairingKeySerParameter pk) {
    if (!pairing.pairing(a, pk.getY()).isEqual(pairing.pairing(pk.getG(), b))) {
      return false;
    }
    for (int i = 0; i < A.size(); i++) {
      if (!pairing.pairing(A.get(i), pk.getY()).isEqual(pairing.pairing(pk.getG(), B.get(i)))) {
        return false;
      }
    }
    return true;
  }

  private boolean cFormedCorrectly(Pairing pairing, Element a, Element b, Element c, List<Element> B, CL04SignPublicPairingKeySerParameter pk) {
    final Element product = pairing.getGT().newOneElement();
    for (int i = 1; i < messages.size(); i++) {
      product.mul(pairing.pairing(pk.getX(), B.get(i)).powZn(messages.get(i)));
    }
    final Element lhs = pairing.pairing(pk.getX(), a)
            .mul(pairing.pairing(pk.getX(), b).powZn(messages.get(0)))
            .mul(product);
    return lhs.isEqual(pairing.pairing(pk.getG(), c));
  }

  /**
   * @description: generate zero-knowledge proof of commitment
   * @param: pk
   * @return: byte[]
   * @throws:
   **/
  public byte[] generateCommitmentProof() {
    try {
      CL04SignPublicPairingKeySerParameter pk = (CL04SignPublicPairingKeySerParameter) pairingKeySerParameter;
      Pairing pairing = PairingFactory.getPairing(pk.getParameters());

      final List<Element> r = new ArrayList<>(); // r contains the list of random numbers
      final Element R = computeR(pk, pairing, r);
      final Element c = computeC(pk, pairing, R);
      final List<Element> s = computeS(r, c);

      Element[] proofElements = new Element[1 + messages.size()];
      proofElements[0] = c;
      for (int i = 0; i < s.size(); i++) {
        proofElements[1 + i] = s.get(i);
      }
      return derEncodeProof(proofElements);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  private byte[] derEncodeProof(Element[] proofElements) throws IOException {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (int i = 0; i < proofElements.length; i++) {
      v.add(new DERPrintableString(Hex.toHexString(proofElements[i].toBytes())));
    }
    return new DERSequence(v).getEncoded(ASN1Encoding.DER);
  }

  private Element[] derDecodeProof(byte[] encoding) throws IOException {
    ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
    PairingParameters params = this.pairingKeySerParameter.getParameters();
    Pairing pairing = PairingFactory.getPairing(params);
    Element[] proofElements = new Element[1 + messages.size()];
    for (int i = 0; i < proofElements.length; i++) {
      proofElements[i] = pairing.getZr().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(i)).getString())).getImmutable();
    }
    return proofElements;
  }

  public Element computeR(final CL04SignPublicPairingKeySerParameter pk, final Pairing pairing, final List<Element> r) {
    r.add(pairing.getZr().newRandomElement().getImmutable());
    Element R = pk.getG().powZn(r.get(0));
    for (int i = 1; i < messages.size(); i++) {
      r.add(pairing.getZr().newRandomElement().getImmutable());
      R = R.mul(pk.getZ().get(i).powZn(r.get(i)));
    }
    return R;
  }

  public Element computeR2(final CL04SignPublicPairingKeySerParameter pk, final Pairing pairing, final Element c, final List<Element> s) {
    Element R2 = pk.getG().powZn(s.get(0));
    for (int i = 1; i < s.size(); i++) {
      R2 = R2.mul(pk.getZ().get(i).powZn(s.get(i)));
    }
    R2 = R2.mul(commitment.powZn(c));
    return R2;
  }

  /**
   * @description: compute the challege which is analogous to the c=Hash(M,R) in the non-interactive schnorr schame
   * @param: commitment
   * @param: R
   * @param: pk
   * @return: it.unisa.dia.gas.jpbc.Element
   * @throws:
   **/
  public Element computeC(final CL04SignPublicPairingKeySerParameter pk, final Pairing pairing, final Element R) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] hash = digest.digest((pk.getG().toString() + pk.getZ().toString() + R.toString() + commitment.toString()).getBytes());
      return pairing.getZr().newElementFromBytes(hash).getImmutable();
    } catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * @description: compute the openings of each messages
   * @param: r
   * @param: messages
   * @param: c
   * @return: List<Element>
   * @throws:
   **/
  public List<Element> computeS(final List<Element> r, final Element c) {
    final List<Element> s = new ArrayList<>();
    for (int i = 0; i < r.size(); i++) {
      s.add(r.get(i).sub(this.messages.get(i).mul(c)));
    }
    return s;
  }

  public boolean verifyCommitmentProof(final byte[] proof) {
    try {
      CL04SignPublicPairingKeySerParameter pk = (CL04SignPublicPairingKeySerParameter) pairingKeySerParameter;
      Pairing pairing = PairingFactory.getPairing(pk.getParameters());
      Element[] proofElements = derDecodeProof(proof);
      Element c = proofElements[0];
      List<Element> s = IntStream.range(1, proofElements.length).mapToObj(i -> proofElements[i]).collect(Collectors.toList());

      Element R2 = computeR2(pk, pairing, c, s);
      Element c2 = computeC(pk, pairing, R2);
      return PairingUtils.isEqualElement(c, c2);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return false;

  }

}
