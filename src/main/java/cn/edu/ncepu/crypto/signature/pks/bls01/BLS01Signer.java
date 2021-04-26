package cn.edu.ncepu.crypto.signature.pks.bls01;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.signature.pks.PairingSigner;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham short signature scheme.
 */
public class BLS01Signer implements PairingSigner {
  /**
   *
   */
  private static final long serialVersionUID = 168480488352794000L;
  public static final String SCHEME_NAME = "Boneh-Lynn-Shacham-01 signature scheme";
  private PairingKeySerParameter pairingKeySerParameter;
  private PairingKeySerParameter[] pairingKeySerParameterArray;

  @Override
  public void init(boolean forSigning, CipherParameters param) {
    if (forSigning) {
      this.pairingKeySerParameter = (BLS01SignSecretPairingKeySerParameter) param;
    } else {
      this.pairingKeySerParameter = (BLS01SignPublicPairingKeySerParameter) param;
    }
  }

  @Override
  public void init(boolean forSigning, CipherParameters[] paramArray) {
    this.pairingKeySerParameterArray = new PairingKeySerParameter[paramArray.length];
    if (forSigning) {
      for (int i = 0; i < paramArray.length; i++) {
        this.pairingKeySerParameterArray[i] = (BLS01SignSecretPairingKeySerParameter) paramArray[i];
      }
    } else {
      for (int i = 0; i < paramArray.length; i++) {
        this.pairingKeySerParameterArray[i] = (BLS01SignPublicPairingKeySerParameter) paramArray[i];
      }
    }
  }

  @Override
  public Element[] generateSignature(byte[] message) {
    PairingParameters params = this.pairingKeySerParameter.getParameters();
    Pairing pairing = PairingFactory.getPairing(params);
    BLS01SignSecretPairingKeySerParameter secretKeyParameters = (BLS01SignSecretPairingKeySerParameter) this.pairingKeySerParameter;
    Element x = secretKeyParameters.getX();
    Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G1);
    Element sigma = m.powZn(x).getImmutable();
    return new Element[]{sigma};
  }

  @Override
	public Element[] batchGenerateSignature(byte[][] messageArray) {
		PairingParameters params = this.pairingKeySerParameterArray[0].getParameters();
		Pairing pairing = PairingFactory.getPairing(params);
    Element[] sigmaArray = new Element[messageArray.length];
    for (int i = 0; i < messageArray.length; i++) {
      BLS01SignSecretPairingKeySerParameter secretKeyParameters = (BLS01SignSecretPairingKeySerParameter) this.pairingKeySerParameterArray[i];
      Element x = secretKeyParameters.getX();
      Element m = PairingUtils.MapByteArrayToGroup(pairing, messageArray[i], PairingUtils.PairingGroupType.G1);
      sigmaArray[i] = m.powZn(x).getImmutable();
    }
    return sigmaArray;
  }

  @Override
  public boolean verifySignature(byte[] message, Element... signature) {
    PairingParameters params = this.pairingKeySerParameter.getParameters();
    Pairing pairing = PairingFactory.getPairing(params);
    BLS01SignPublicPairingKeySerParameter publicKeyParameters = (BLS01SignPublicPairingKeySerParameter) this.pairingKeySerParameter;
    Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G1);
    Element g = publicKeyParameters.getG();
    Element v = publicKeyParameters.getV();
    Element sigma = signature[0];
    Element temp1 = pairing.pairing(sigma, g);
    Element temp2 = pairing.pairing(m, v);
		return PairingUtils.isEqualElement(temp1, temp2);
	}

	@Override
	public boolean batchVerifySignature(byte[][] messageArray, Element[] signatureArray) {
		PairingParameters params = this.pairingKeySerParameterArray[0].getParameters();
		Pairing pairing = PairingFactory.getPairing(params);
		Element g = ((BLS01SignPublicPairingKeySerParameter) this.pairingKeySerParameterArray[0]).getG();
		Element sigmaMulProduct = pairing.getG1().newOneElement();
		Element temp2 = pairing.getGT().newOneElement();
		for (int i = 0; i < messageArray.length; i++) {
			BLS01SignPublicPairingKeySerParameter publicKeyParameters = (BLS01SignPublicPairingKeySerParameter) this.pairingKeySerParameterArray[i];
			Element vi = publicKeyParameters.getV();
			sigmaMulProduct = sigmaMulProduct.mul(signatureArray[i]);
			Element hi = PairingUtils.MapByteArrayToGroup(pairing, messageArray[i], PairingUtils.PairingGroupType.G1);
			temp2 = temp2.mul(pairing.pairing(hi, vi));
		}
		Element temp1 = pairing.pairing(sigmaMulProduct, g);
		return PairingUtils.isEqualElement(temp1, temp2);
	}

	public byte[] derEncode(Element[] signElements) throws IOException {
		return ((CurveElement<?, ?>) signElements[0]).toBytesCompressed();
	}

	public byte[][] derBatchEncode(Element[] signElements) throws IOException {
		byte[][] encodingArray = new byte[signElements.length][];
		for (int i = 0; i < signElements.length; i++) {
			encodingArray[i] = ((CurveElement<?, ?>) signElements[i]).toBytesCompressed();
		}
		return encodingArray;
	}

	/**
	 * @param encoding:
	 * @description: decode byte signature into CurveElement signature
	 * @return: it.unisa.dia.gas.jpbc.Element[]
	 * @throws:
	 **/
	public Element[] derDecode(byte[] encoding) throws IOException {
		PairingParameters params = this.pairingKeySerParameter.getParameters();
		Pairing pairing = PairingFactory.getPairing(params);
		Element signature = pairing.getG1().newZeroElement();
		((CurveElement<?, ?>) signature).setFromBytesCompressed(encoding);
		return new Element[]{signature,};
	}

	@Override
	public Element[] derBatchDecode(byte[][] encodingArray) throws IOException {
		PairingParameters params = this.pairingKeySerParameterArray[0].getParameters();
		Pairing pairing = PairingFactory.getPairing(params);
		Element[] signatures = new Element[encodingArray.length];
		for (int i = 0; i < encodingArray.length; i++) {
			signatures[i] = pairing.getG1().newZeroElement();
			((CurveElement<?, ?>) signatures[i]).setFromBytesCompressed(encodingArray[i]);
		}
		return signatures;
	}

	public String getEngineName() {
		return SCHEME_NAME;
	}
}