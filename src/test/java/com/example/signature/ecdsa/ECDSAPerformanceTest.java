package com.example.signature.ecdsa;

import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSAKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSAKeySerPairGenerator;
import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;
import cn.edu.ncepu.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * @author 胡柏吉
 * @version 1.0
 * @description TODO
 * @date 2020-10-30 下午1:03
 * @email drbjhu@163.com
 */
public class ECDSAPerformanceTest {
    private static final Logger logger = LoggerFactory.getLogger(ECDSAPerformanceTest.class);
    private static final String USER_DIR = SysProperty.USER_DIR;
    // file path for performance test result
    private static final String default_path = "benchmarks/signature/ecdsa/";
    // test round
    private static long test_round = 1_000L;
    // keyGen time
    private double timeKeyGen;
    // sign time
    private double timeSign;
    // verify time
    private double timeVerify;

    Signer signer;
    private String SCHEME_NAME;

    private Out out;

    private AsymmetricKeySerPairGenerator asymmetricKeySerPairGenerator;

    private void runPerformanceTest() {
        out = new Out(default_path + this.SCHEME_NAME);
        out.println("Test ECDSA signer: " + ECDSASigner.SCHEME_NAME);
        out.println("All test rounds: " + this.test_round);
        logger.info("All test rounds: " + this.test_round);
        for (int i = 0; i < test_round; i++) {
            logger.info("Test round: " + (i + 1));
            out.println("Test round: " + (i + 1));
            run_one_round();
        }
        logger.info("average keyGen time: " + this.timeKeyGen / test_round);
        out.println("average keyGen time: " + this.timeKeyGen / test_round);
        logger.info("average sign time:   " + this.timeSign   / test_round);
        out.println("average sign time:   " + this.timeSign   / test_round);
        logger.info("average verify time: " + this.timeVerify / test_round);
        out.println("average verify time: " + this.timeVerify / test_round);
    }

    private void run_one_round() {
        try {
            double temperTime;
            Timer timer = new Timer();

            // test keyGen performance
            out.print("KeyGen :");
            timer.start(0);
            AsymmetricKeySerPair asymmetricKeySerPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
            AsymmetricKeySerParameter publicKey = asymmetricKeySerPair.getPublic();
            AsymmetricKeySerParameter secretKey = asymmetricKeySerPair.getPrivate();
            temperTime = timer.stop(0);
            logger.info("KeyGen; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeKeyGen += temperTime;

            // test sign performance
            out.print("Sign : ");
            timer.start(0);
            byte[] message = "Message".getBytes(StandardCharsets.UTF_8);
            signer.init(true, secretKey);
            signer.update(message, 0, message.length);
            byte[] signature = signer.generateSignature();
            temperTime = timer.stop(0);
            logger.info("Sign; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeSign += temperTime;

            // test verify performance
            out.print("Verify : ");
            timer.start(0);
            signer.init(false, publicKey);
            signer.update(message, 0, message.length);
            if (!signer.verifySignature(signature)) {
                logger.info("cannot verify valid signature, test abort...");
                System.exit(0);
            }
            temperTime = timer.stop(0);
            logger.info("Verify; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeVerify += temperTime;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Ignore
    @Test
    public void testECDSAPerformance() {
        ECDSAPerformanceTest performanceTest = new ECDSAPerformanceTest();
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_256_1024);
        performanceTest.asymmetricKeySerPairGenerator = new ECDSAKeySerPairGenerator();
        performanceTest.asymmetricKeySerPairGenerator.init(new ECDSAKeyPairGenerationParameter(null, 32, pairingParameters));
        performanceTest.signer = new ECDSASigner(new SHA256Digest());
        performanceTest.SCHEME_NAME = ECDSASigner.SCHEME_NAME;
        performanceTest.runPerformanceTest();
    }
}
