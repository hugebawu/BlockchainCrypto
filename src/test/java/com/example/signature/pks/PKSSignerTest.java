package com.example.signature.pks;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.signature.pks.PairingDigestSigner;
import cn.edu.ncepu.crypto.signature.pks.bb04.BB04SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bb04.BB04SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bb04.BB04Signer;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bb08.BB08Signer;
import cn.edu.ncepu.crypto.signature.pks.bls01.BLS01SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.pks.bls01.BLS01SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.pks.bls01.BLS01Signer;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * <p>Public key signature test.
 */
public class PKSSignerTest {
  private static final Logger logger = LoggerFactory.getLogger(PKSSignerTest.class);
  private PairingKeyPairGenerator asymmetricKeySerPairGenerator;
  private Signer signer;

  private void processTest() {
    // KeyGen
    PairingKeySerPair keyPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
    PairingKeySerParameter publicKey = keyPair.getPublic();
    PairingKeySerParameter secretKey = keyPair.getPrivate();

    logger.info("========================================");
    logger.info("Test signer functionality");
    try {
      // signature
      byte[] message = "Message".getBytes(StandardCharsets.UTF_8);
      signer.init(true, secretKey);
      signer.update(message, 0, message.length);
      byte[] signature = signer.generateSignature();
      logger.info("Signature length = " + signature.length + " byte");

      byte[] messagePrime = "MessagePrime".getBytes(StandardCharsets.UTF_8);
      signer.init(true, secretKey);
      signer.update(messagePrime, 0, messagePrime.length);
      byte[] signaturePrime = signer.generateSignature();
      logger.info("Signature' length = " + signaturePrime.length + " byte");
      // verify
      signer.init(false, publicKey);
      signer.update(message, 0, message.length);
      if (!signer.verifySignature(signature)) {
        logger.info("cannot verify valid signature, test abort...");
        System.exit(0);
      }
      // verify
      signer.init(false, publicKey);
      signer.update(messagePrime, 0, messagePrime.length);
      if (!signer.verifySignature(signaturePrime)) {
        logger.info("Verify passed for invalid signature, test abort...");
        System.exit(0);
      }
    } catch (CryptoException e) {
      e.printStackTrace();
    }
    logger.info("Pairing signer functionality test pass.");
    logger.info("========================================");
    logger.info("Test signer parameters serialization & de-serialization.");
    try {
      // serialize public key
      logger.info("Test serialize & de-serialize public key.");
      byte[] byteArrayPublicKey = CommonUtils.SerObject(publicKey);
      CipherParameters anPublicKey = (CipherParameters) CommonUtils.deserObject(byteArrayPublicKey);
      assertEquals(publicKey, anPublicKey);
      // serialize secret key
      logger.info("Test serialize & de-serialize secret keys.");
      // serialize sk
      byte[] byteArraySecretKey = CommonUtils.SerObject(secretKey);
      CipherParameters anSecretKey = (CipherParameters) CommonUtils.deserObject(byteArraySecretKey);
      assertEquals(secretKey, anSecretKey);
      logger.info("Signer parameter serialization tests passed.");
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }

  @Ignore
  @Test
  public void testBLS01Signer() {
    PairingParameters pairingParameters =
            PairingFactory.getPairingParameters(PairingUtils.PATH_f_256);
    logger.info("Test Boneh-Lynn-Shacham 2001 signature.");
    this.asymmetricKeySerPairGenerator = new BLS01SignKeyPairGenerator();
    this.asymmetricKeySerPairGenerator.init(
            new BLS01SignKeyPairGenerationParameter(pairingParameters));
    this.signer = new PairingDigestSigner(new BLS01Signer(), new SHA256Digest());
    this.processTest();
  }

  /*
   * test time overhead of exponential operation in G1
   * @return: void
   * @throws:
   **/
  @Test
  public void testBLS01BatchSignAndVerify() {
    PairingParameters pairingParameters =
            PairingFactory.getPairingParameters(PairingUtils.PATH_f_256);
    logger.info("Test Boneh-Lynn-Shacham 2001 batch signature verify.");
    BLS01SignKeyPairGenerator bls01SignKeyPairGenerator = new BLS01SignKeyPairGenerator();
    bls01SignKeyPairGenerator.init(new BLS01SignKeyPairGenerationParameter(pairingParameters));
    int omega = 10; // number of users
    PairingDigestSigner pairingDigestSigner =
            new PairingDigestSigner(new BLS01Signer(), new SHA256Digest());
    try {
      byte[][] msgArray = new byte[omega][]; // message remains to be signed
      for (int i = 0; i < msgArray.length; i++) {
        byte[] msg = new byte[0];
        msg = ("Message" + String.valueOf(i)).getBytes("UTF-8");
        msgArray[i] = new byte[msg.length];
        System.arraycopy(msg, 0, msgArray[i], 0, msg.length);
      }
      // batch key generate
      PairingKeySerPair[] pairingKeySerPairArray =
              bls01SignKeyPairGenerator.batchGenerateKeyPair(omega);
      PairingKeySerParameter[] publicKeyArray = new PairingKeySerParameter[omega];
      PairingKeySerParameter[] secretKeyArray = new PairingKeySerParameter[omega];
      for (int i = 0; i < omega; i++) {
        publicKeyArray[i] = pairingKeySerPairArray[i].getPublic();
        secretKeyArray[i] = pairingKeySerPairArray[i].getPrivate();
      }
      // batch signature generate
      pairingDigestSigner.init(true, secretKeyArray);
      byte[][] signatureArray = pairingDigestSigner.batchGenerateSignature(msgArray);
      // batch signature verify
      pairingDigestSigner.init(false, publicKeyArray);
      if (!pairingDigestSigner.batchVerifySignature(msgArray, signatureArray)) {
        logger.info("cannot batch verify valid signature, test abort...");
        System.exit(0);
      }
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    logger.info("BLS01 batch signature and verification functionality test pass.");
  }

  @Ignore
  @Test
  public void testBB04Signer() {
    PairingParameters pairingParameters =
            PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
    logger.info("Test Boneh-Boyen 2004 signature.");
    this.asymmetricKeySerPairGenerator = new BB04SignKeyPairGenerator();
    this.asymmetricKeySerPairGenerator.init(
            new BB04SignKeyPairGenerationParameter(pairingParameters));
    this.signer = new PairingDigestSigner(new BB04Signer(), new SHA256Digest());
    this.processTest();
  }

  @Ignore
  @Test
  public void testBB08Signer() {
    PairingParameters pairingParameters =
            PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
    logger.info("Test Boneh-Boyen 2008 signature.");
    this.asymmetricKeySerPairGenerator = new BB08SignKeyPairGenerator();
    this.asymmetricKeySerPairGenerator.init(
            new BB08SignKeyPairGenerationParameter(pairingParameters));
    this.signer = new PairingDigestSigner(new BB08Signer(), new SHA256Digest());
    this.processTest();
  }
}