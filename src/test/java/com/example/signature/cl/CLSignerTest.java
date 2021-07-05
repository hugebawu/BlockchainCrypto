package com.example.signature.cl;

import cn.edu.ncepu.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.signature.cl.CL04SignKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.cl.CL04SignKeyPairGenerator;
import cn.edu.ncepu.crypto.signature.cl.CL04Signer;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/7/2 21:13
 *//*
 * @ClassName CLSignerTest
 * @Description TODO
 * @Author Administrator
 * @Date 2021/7/2 21:13
 * @Version 1.0
 */
public class CLSignerTest {
    private static final Logger logger = LoggerFactory.getLogger(CLSignerTest.class);
    private PairingKeyPairGenerator pairingKeySerPairGenerator;
    private CL04Signer signer;
    private final int messageSize = 5;

    private void processTest() {
        // KeyGen
        PairingKeySerPair keyPair = this.pairingKeySerPairGenerator.generateKeyPair();
        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter secretKey = keyPair.getPrivate();
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        try {
            // generate commitment
            final List<Element> messages = IntStream.range(0, messageSize)
                    .mapToObj(i -> pairing.getZr().newRandomElement().getImmutable())
                    .collect(Collectors.toList());
            signer.init(false, publicKey);
            signer.setCommitment(signer.generateCommit(messages));
            signer.setMessages(messages);

            logger.info("========================================");
            logger.info("Test Schnorr NIZK Proof functionality");
            // generate proof of commitment
            byte[] proof = signer.generateCommitmentProof();
            logger.info("ZK Proof length = " + proof.length + " byte");

            // verify proof of commitment
            if (!signer.verifyCommitmentProof(proof)) {
                logger.info("cannot verify valid proof, test abort...");
                System.exit(0);
            }
            logger.info("Schnorr NIZK proof functionality test pass.");

            logger.info("========================================");
            logger.info("Test CLSigner functionality");
            // signature
            signer.init(true, secretKey);
            byte[] signature = signer.generateSignature();
            logger.info("Signature length = " + signature.length + " byte");

            // verify
            signer.init(false, publicKey);
            if (!signer.verifySignature(signature)) {
                logger.info("cannot verify valid signature, test abort...");
                System.exit(0);
            }
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        logger.info("CL04 Pairing signer functionality test pass.");
        logger.info("========================================");
        logger.info("Test CL04Signer parameters serialization & de-serialization.");
        try {
            // serialize secret key
            logger.info("Test serialize & de-serialize secret keys.");
            // serialize sk
            byte[] byteArraySecretKey = CommonUtils.SerObject(secretKey);
            CipherParameters anSecretKey = (CipherParameters) CommonUtils.deserObject(byteArraySecretKey);
            assertTrue(secretKey.equals(anSecretKey));
            // serialize public key
            logger.info("Test serialize & de-serialize public key.");
            byte[] byteArrayPublicKey = CommonUtils.SerObject(publicKey);
            CipherParameters anPublicKey = (CipherParameters) CommonUtils.deserObject(byteArrayPublicKey);
            assertEquals(publicKey, anPublicKey);
            logger.info("Signer parameter serialization tests passed.");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    @Test
    public void testCL04Signer() {
        PairingParameters pairingParameters =
                PairingFactory.getPairingParameters(PairingUtils.PATH_a_256_1024);
        logger.info("Test Camenisch-Lysyanskaya-2004 signature signature.");
        this.pairingKeySerPairGenerator = new CL04SignKeyPairGenerator(messageSize);
        this.pairingKeySerPairGenerator.init(
                new CL04SignKeyPairGenerationParameter(pairingParameters));
        this.signer = new CL04Signer(new SHA256Digest());
        this.processTest();
    }

}
