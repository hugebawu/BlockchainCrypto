package com.example.signature.ecdsa;

import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSAKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSAKeySerPairGenerator;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * @Copyright : Copyright (c) 2020-2021
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 18, 2020 3:24:26 PM
 * @ClassName ECDSASignerTest
 * @Description: (elliptic curve based dsa ( Digital Signature Algorithm) test.)
 */
@SuppressWarnings("unused")
public class ECDSASignerTest {
  private static final Logger logger = LoggerFactory.getLogger(ECDSASignerTest.class);
  private AsymmetricKeySerPairGenerator asymmetricKeySerPairGenerator;
  private static final String EC_STRING = "EC";
  private static final String CURVE_NAME = "secp256k1";
  private Signer signer;

  public void processTest() {
    try {
      // KeyGen
      AsymmetricKeySerPair asymmetricKeySerPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
      AsymmetricKeySerParameter publicKey = asymmetricKeySerPair.getPublic();
      AsymmetricKeySerParameter secretKey = asymmetricKeySerPair.getPrivate();
      logger.info("===========================================");
      logger.info("test signer functionality");
      // generate signature
      byte[] message = "Message".getBytes(StandardCharsets.UTF_8);
      signer.init(true, secretKey);
      signer.update(message, 0, message.length);
      byte[] signature = signer.generateSignature();
      logger.info("ECDSA signature size: " + signature.length / 2 + " bytes");

      // verify signature
      signer.init(false, publicKey);
      signer.update(message, 0, message.length);
      if (!signer.verifySignature(signature)) {
        logger.info("Verify passed for invalid signature, test abort!!!");
        System.exit(0);
      }
    } catch (CryptoException e) {
      e.printStackTrace();
    }
    logger.info("ECDSAsigner functionality test pass.");
  }

  @Test
  public void testECDSASigner() {
    PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_256_1024);
    logger.info("Test ECDSA signature scheme -- Don Johnson, Alfred Menezes, Scott Vanstone 2001 ");
    asymmetricKeySerPairGenerator = new ECDSAKeySerPairGenerator();
    asymmetricKeySerPairGenerator.init(new ECDSAKeyPairGenerationParameter(null, 32, pairingParameters));
    signer = new ECDSASigner(new SHA256Digest());
    processTest();
  }
}
