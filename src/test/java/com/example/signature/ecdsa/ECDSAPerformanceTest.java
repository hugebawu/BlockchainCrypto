package com.example.signature.ecdsa;

import cn.edu.ncepu.crypto.signature.ecdsa.ECDSASigner;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.EccUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;
import cn.edu.ncepu.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.bouncycastle.crypto.Signer;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

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
    private static final String EC_STRING = "EC";
    // file path for performance test result
    private static final String default_path = "benchmarks/signature/ecdsa/";
    // test round
    private static int test_round = 100_00;
    // keyGen time
    private double timeKeyGen;
    // sign time
    private double timeSign;
    // verify time
    private double timeVerify;

    Signer signer;

    private Out out;



    private void runPerformanceTest() {
        out = new Out(default_path + ECDSASigner.SCHEME_NAME);
        out.println("Test ECDSA signer: " + ECDSASigner.SCHEME_NAME);
        out.println("All test rounds: " + this.test_round);
        for (int i = 0; i < test_round; i++) {
            logger.info("Test round: " + (i + 1));
            out.println("Test round: " + (i + 1));
            run_one_round();
        }
        logger.info("average keyGen time: " + this.timeKeyGen * 1.0 / test_round);
        out.println("average keyGen time: " + this.timeKeyGen * 1.0 / test_round);
        logger.info("average sign time:   " + this.timeSign   * 1.0 / test_round);
        out.println("average sign time:   " + this.timeSign   * 1.0 / test_round);
        logger.info("average verify time: " + this.timeVerify * 1.0 / test_round);
        out.println("average verify time: " + this.timeVerify * 1.0 / test_round);
    }

    private void run_one_round() {
        try {
            double temperTime;
            Timer timer = new Timer();

            // test keyGen performance
            out.print("KeyGen :");
            timer.start(0);
            KeyPair keyPair = EccUtils.getKeyPair(256);
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            temperTime  = timer.stop(0);
            logger.info("KeyGen; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeKeyGen += temperTime;

            // test sign performance
            out.print("Sign : ");
            String hash = DigestUtils.sha256Hex("message");

            timer.start(0);
            byte[] sign = ECDSASigner.sign(privateKey, hash.getBytes("UTF-8"));
            temperTime = timer.stop(0);
            logger.info("Sign; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeSign += temperTime;

            // test verify performance
            out.print("Verify : ");
            timer.start(0);
            ECDSASigner.verify(publicKey, hash.getBytes(), sign);
            temperTime = timer.stop(0);
            logger.info("Verify; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeVerify += temperTime;

        } catch (Exception e) {
            e.printStackTrace();
        }


    }

//    @Ignore
    @Test
    public void testECDSAPerformance() {
        ECDSAPerformanceTest performanceTest = new ECDSAPerformanceTest();
        performanceTest.runPerformanceTest();
    }

    @Ignore
    @Test
    public void testSignTimeCost() {
        String message = "NACCFFFFFFFF";
        String hexString = DigestUtils.sha256Hex(message);
        ECPrivateKey privateKey = null;
        try {
            privateKey = (ECPrivateKey) CommonUtils.loadKeyFromPEM(false, EC_STRING,
                    USER_DIR + "/elements/ECPrivateKey.pem");
            byte[] bytes = hexString.getBytes(StandardCharsets.UTF_8);
            StopWatch watch = new StopWatch();
            watch.start();
            for (int i = 0; i < test_round; i++) {
                ECDSASigner.sign(privateKey, bytes);
            }
            watch.stop();
            logger.info("average ECDSA sign: " + watch.getTime() * 1.0 / test_round);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (SignatureException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }

    @Ignore
    @Test
    public void testVerifyTimeCost() {
        String message = "NACCFFFFFFFF";
        String hexString = DigestUtils.sha256Hex(message);
        ECPublicKey publicKey = null;
        ECPrivateKey privateKey = null;
        try {
            publicKey = (ECPublicKey) CommonUtils.loadKeyFromPEM(true, EC_STRING,
                    USER_DIR + "/elements/ECPublicKey.pem");
            privateKey = (ECPrivateKey) CommonUtils.loadKeyFromPEM(false, EC_STRING,
                    USER_DIR + "/elements/ECPrivateKey.pem");
            byte[] bytes = hexString.getBytes("UTF-8");
            byte[] sign = ECDSASigner.sign(privateKey, bytes);
            StopWatch watch = new StopWatch();
            watch.start();
            for (int i = 0; i < test_round; i++) {
                ECDSASigner.verify(publicKey, bytes, sign);
            }
            watch.stop();
            logger.info("average ECDSA verify: " + watch.getTime() * 1.0 / test_round);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (SignatureException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        } catch (DecoderException e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }
}
