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
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;
import cn.edu.ncepu.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

/**
 * @author 胡柏吉
 * @version 1.0
 * @description TODO
 * @date 2020-10-30 下午2:57
 * @email drbjhu@163.com
 */
public class PKSPerformanceTest {
    private static final Logger logger = LoggerFactory.getLogger(PKSPerformanceTest.class);
    private PairingKeyPairGenerator asymmetricKeySerPairGenerator;
    private Signer signer;
    private String  SCHEME_NAME;

    private static final String USER_DIR = SysProperty.USER_DIR;

    private String pairingParameterPath;
    // file path for performance test result
    private static final String default_path = "benchmarks/signature/pks/";
    // test round
    private static final long test_round = 100L;
    // keyGen time
    private double timeKeyGen;
    // sign time
    private double timeSign;
    // verify time
    private double timeVerify;

    private Out out;

    private void runPerformanceTest() {
        this.out = new Out(default_path + this.SCHEME_NAME);
        this.out.println("Test signer: " + this.SCHEME_NAME);
        this.out.println("All test rounds: " + this.test_round);
        for (int i = 0; i < test_round; i++) {
            logger.info("Test round: " + (i + 1));
            out.println("Test round: " + (i + 1));
            run_one_round();
            logger.info("");
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
            out.print("keyGen :");
            timer.start(0);
            PairingKeySerPair keyPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
            PairingKeySerParameter publicKey = keyPair.getPublic();
            PairingKeySerParameter secretKey = keyPair.getPrivate();
            temperTime = timer.stop(0);
            logger.info("keyGen; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeKeyGen += temperTime;

            // test sign performance
            // String hash = DigestUtils.sha256Hex("message");
            out.print("Sign : ");
            timer.start(0);
            byte[] message = "Message".getBytes("UTF-8");
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
        } catch (CryptoException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    @Ignore
    @Test
    public void testBLS01Performance() {
        PKSPerformanceTest performanceTest = new PKSPerformanceTest();
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_f_256);
        performanceTest.asymmetricKeySerPairGenerator = new BLS01SignKeyPairGenerator();
        performanceTest.asymmetricKeySerPairGenerator.init(new BLS01SignKeyPairGenerationParameter(pairingParameters));
        performanceTest.signer = new PairingDigestSigner(new BLS01Signer(), new SHA256Digest());
        performanceTest.SCHEME_NAME = BLS01Signer.SCHEME_NAME;
        performanceTest.runPerformanceTest();
    }

    @Ignore
    @Test
    public void testBB04Performance() {
        PKSPerformanceTest performanceTest = new PKSPerformanceTest();
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_256_1024);
        performanceTest.asymmetricKeySerPairGenerator = new BB04SignKeyPairGenerator();
        performanceTest.asymmetricKeySerPairGenerator.init(new BB04SignKeyPairGenerationParameter(pairingParameters));
        performanceTest.signer = new PairingDigestSigner(new BB04Signer(), new SHA256Digest());
        performanceTest.SCHEME_NAME = BB04Signer.SCHEME_NAME;
        performanceTest.runPerformanceTest();
    }

    @Ignore
    @Test
    public void testBB08Performance() {
        PKSPerformanceTest performanceTest = new PKSPerformanceTest();
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_256_1024);
        performanceTest.asymmetricKeySerPairGenerator = new BB08SignKeyPairGenerator();
        performanceTest.asymmetricKeySerPairGenerator.init(new BB08SignKeyPairGenerationParameter(pairingParameters));
        performanceTest.signer = new PairingDigestSigner(new BB08Signer(), new SHA256Digest());
        performanceTest.SCHEME_NAME = BB08Signer.SCHEME_NAME;
        performanceTest.runPerformanceTest();
    }
}
