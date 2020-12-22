package com.example.homomorphicencryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/21 9:17
 */

import cn.edu.ncepu.crypto.encryption.bgn.BGNEngine;
import cn.edu.ncepu.crypto.encryption.bgn.BGNKeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.bgn.BGNPrivateKey;
import cn.edu.ncepu.crypto.encryption.bgn.BGNPublicKey;
import cn.edu.ncepu.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.NoSuchPaddingException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * @ClassName BGNPerformanceTest
 * @Description performance test of the BGN cryptosystem
 * @Author Administrator
 * @Date 2020/12/21 9:17
 * @Version 1.0
 **/
public class BGNPerformanceTest {
    private static final Logger logger = LoggerFactory.getLogger(BGNPerformanceTest.class);

    // file path for performance test result
    private static final String default_path = "benchmarks/homomorphicencryption/bgn/";
    // test round
    private final long test_round = 100L;

    // setup time
    private double timeSetup;

    // secret key generation time
    private double timeKeyGen;

    // encryption time
    private double timeEncryption;

    // decryption time
    private double timeDecryption;

    //timeAddition time
    private double timeAddition;

    // timeMultiply time
    private double timeMultiply;

    private static BGNEngine engine;

    private Out out;

    private void runPerformanceTest() {
        out = new Out(default_path + engine.getEngineName());
        out.println("Test engine: " + engine.getEngineName());
        out.println("All test rounds: " + this.test_round);

        for (int i = 0; i < test_round; i++) {
            logger.info("Test round: " + (i + 1));
            out.println("Test round: " + (i + 1));
            run_one_round();
        }
        logger.info("average keyGen time:  " + this.timeKeyGen / test_round);
        out.println("average keyGen time:  " + this.timeKeyGen / test_round);
        logger.info("average encrypt time: " + this.timeEncryption / test_round);
        out.println("average encrypt time: " + this.timeEncryption / test_round);
        logger.info("average decrypt time: " + this.timeDecryption / test_round);
        out.println("average decrypt time: " + this.timeDecryption / test_round);
        logger.info("average addition time:" + this.timeAddition / test_round);
        out.println("average addition time:" + this.timeAddition / test_round);
        logger.info("average multiply time:" + this.timeMultiply / test_round);
        out.println("average multiply time:" + this.timeMultiply / test_round);
    }

    private void run_one_round() {
        try {
            double temperTime;
            Timer timer = new Timer();

            // test key generation performance
            out.print("KeyGen: ");
            timer.start(0);
            BGNKeyPairGenerator kpg = new BGNKeyPairGenerator();
            kpg.initialize(64, null);
            KeyPair keyPair = kpg.generateKeyPair();
            BGNPublicKey pubKey = (BGNPublicKey) keyPair.getPublic();
            BGNPrivateKey privKey = (BGNPrivateKey) keyPair.getPrivate();
            temperTime = timer.stop(0);
            logger.info("KeyGen;" + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeKeyGen += temperTime;

            int m1 = 5;
            int m2 = 6;

            // test encryption performance
            out.print("Encryption: ");
            timer.start(0);
            Element c1 = engine.encrypt(m1, pubKey);
            temperTime = timer.stop(0);
            logger.info("Encryption; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeEncryption += temperTime;

            Element c2 = engine.encrypt(m1, pubKey);

            // test decryption performance
            out.print("Decryption: ");
            timer.start(0);
            int decrypted_m1 = engine.decrypt(c1, pubKey, privKey);
            temperTime = timer.stop(0);
            logger.info("Decryption; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeDecryption += temperTime;

            // test addition performance
            out.print("Addition");
            timer.start(0);
            // product
            Element c1mulc2 = engine.add(c1, c2);
            temperTime = timer.stop(0);
            logger.info("Addition; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeAddition += temperTime;

            // test multiply performance
            out.print("Multiply");
            timer.start(0);
            // pairing
            Element c1pairingc2 = engine.mul2(c1, c2, pubKey);
            temperTime = timer.stop(0);
            logger.info("Multiply; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeMultiply += temperTime;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testBGNPerformance() {
        BGNPerformanceTest performanceTest = new BGNPerformanceTest();
        performanceTest.engine = BGNEngine.getInstance();
        performanceTest.runPerformanceTest();
    }
}
