package com.example.signature.ecdsa;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.EccUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.ImmutableCurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

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
	private PairingKeyPairGenerator asymmetricKeySerPairGenerator;
	private static final String EC_STRING = "EC";
	private static final String CURVE_NAME = "secp256k1";
	private Signer signer;


	@Test
	public void testECDSASigner() {
		try {
			// keyGen
			KeyPair keyPair = CommonUtils.initKey(EC_STRING, CURVE_NAME);
//			KeyPair keyPair = EccUtils.getKeyPair(256);

			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

			// 生成一个Base64编码的公钥字符串，可用来传输
			String ecBase64PublicKey = EccUtils.publicKey2String(publicKey);
			String ecBase64PrivateKey = EccUtils.privateKey2String(privateKey);
			logger.info("[publickey]:\t" + ecBase64PublicKey);
			logger.info("[privateKey]:\t" + ecBase64PrivateKey);

			// 从base64编码的字符串恢复密钥
			ECPublicKey publicKey2 = EccUtils.string2PublicKey(ecBase64PublicKey);
			ECPrivateKey privateKey2 = EccUtils.string2PrivateKey(ecBase64PrivateKey);

			logger.info("Test Scott-Vanstone 1992 signature.");
			logger.info("========================================");
			logger.info("Test signer functionality");

			// signature
			String message = "message";
			String hashString = DigestUtils.sha256Hex(message);
			byte[] sign = ECDSASigner.sign(privateKey2, hashString.getBytes("UTF-8"));
			logger.info("Signature length = " + sign.length + " bytes");
			String signHex = Hex.encodeHexString(sign);
			logger.info("signature: " + signHex);
          logger.info("hex signature length: " + signHex.length());

          // verify
          if (false == ECDSASigner.verify(publicKey2, hashString.getBytes("UTF-8"), sign)) {
            logger.info("Verify passed for invalid signature, test abort...");
            System.exit(0);
          }

          logger.info("ECDSA signer functionality test pass.");

          logger.info("========================================");
          logger.info("Test signer parameters serialization & de-serialization.");
        } catch (InvalidKeyException e) {
          logger.error(e.getLocalizedMessage());
        } catch (DecoderException e) {
          logger.error(e.getLocalizedMessage());
        } catch (InvalidAlgorithmParameterException e) {
          logger.error(e.getLocalizedMessage());
        } catch (NoSuchAlgorithmException e) {
          logger.error(e.getLocalizedMessage());
        } catch (UnsupportedEncodingException e) {
          logger.error(e.getLocalizedMessage());
        } catch (SignatureException e) {
          logger.error(e.getLocalizedMessage());
        } catch (Exception e) {
          logger.error(e.getLocalizedMessage());
        }
    }

  @Test
  public void testECDSA() {
    PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_256_1024);
    
    BigInteger n = pairingParameters.getBigInteger("r");
    BigInteger q = pairingParameters.getBigInteger("q");

    logger.info("n_bitLength: " + n.bitLength());

    Pairing pairing = PairingFactory.getPairing(pairingParameters);

    Field G1_Field = pairing.getG1();
    Field G2_Field = pairing.getG2();
    Field Zr_Field = pairing.getZr();

    int m = 95234549;

    Assert.assertTrue(G1_Field.equals(G2_Field));
    // key Gen
    Element G = G1_Field.newRandomElement().getImmutable();
    Element d = Zr_Field.newRandomElement().getImmutable();
    Element Q = G.powZn(d).getImmutable();

    // generate hash digest
    Digest digest = new SHA256Digest();
    byte[] bytes = BigInteger.valueOf(m).toByteArray();
    digest.update(bytes, 0, bytes.length);
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    // generate signature
    Element k = Zr_Field.newRandomElement().getImmutable();
    ImmutableCurveElement Gk = (ImmutableCurveElement) G.powZn(k);
    Element x1 = Gk.getX();
    Element r = Zr_Field.newElement(x1).getImmutable();
    Element e = Zr_Field.newElement(new BigInteger(hash)).getImmutable();
    Element s = k.invert().mul(e.add(d.mul(r)));
    Assert.assertTrue(s instanceof ZrElement);
    // verify signature
    Element w = s.invert();
    Element u1 = e.mul(w);
    Element u2 = r.mul(w);
    ImmutableCurveElement X = (ImmutableCurveElement) (G.powZn(u1).add(Q.powZn(u2)));
    Element x2 = X.getX();
    Element v = Zr_Field.newElement(x2).getImmutable();
    Assert.assertTrue(v.isEqual(r));
  }

}
