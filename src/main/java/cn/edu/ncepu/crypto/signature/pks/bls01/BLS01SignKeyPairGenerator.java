package cn.edu.ncepu.crypto.signature.pks.bls01;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * <p>Boneh-Lynn-Shacham signature public key / secret key pair generator.
 */
public class BLS01SignKeyPairGenerator implements PairingKeyPairGenerator {
  private BLS01SignKeyPairGenerationParameter param;

  @Override
  public void init(KeyGenerationParameters param) {
    this.param = (BLS01SignKeyPairGenerationParameter) param;
  }

  @Override
  public PairingKeySerPair generateKeyPair() {
    Pairing pairing = PairingFactory.getPairing(this.param.getPairingParameters());

    Element x = pairing.getZr().newRandomElement().getImmutable();
    Element g = pairing.getG2().newRandomElement().getImmutable();
    Element v = g.powZn(x).getImmutable();
    BLS01SignPublicPairingKeySerParameter publicKeyParameters =
            new BLS01SignPublicPairingKeySerParameter(this.param.getPairingParameters(), g, v);
    BLS01SignSecretPairingKeySerParameter secretKeyParameters =
            new BLS01SignSecretPairingKeySerParameter(this.param.getPairingParameters(), x);
    return new PairingKeySerPair(publicKeyParameters, secretKeyParameters);
  }

  public PairingKeySerPair[] batchGenerateKeyPair(int Num) {
    Pairing pairing = PairingFactory.getPairing(this.param.getPairingParameters());
    Element g = pairing.getG2().newRandomElement().getImmutable();
    PairingKeySerPair[] pairingKeySerPairArray = new PairingKeySerPair[Num];
    for (int i = 0; i < Num; i++) {
      Element xi = pairing.getZr().newRandomElement().getImmutable();
      Element vi = g.powZn(xi).getImmutable();
      BLS01SignPublicPairingKeySerParameter publicKeyParameters =
              new BLS01SignPublicPairingKeySerParameter(this.param.getPairingParameters(), g, vi);
      BLS01SignSecretPairingKeySerParameter secretKeyParameters =
              new BLS01SignSecretPairingKeySerParameter(this.param.getPairingParameters(), xi);
      pairingKeySerPairArray[i] = new PairingKeySerPair(publicKeyParameters, secretKeyParameters);
    }
    return pairingKeySerPairArray;
  }
}
