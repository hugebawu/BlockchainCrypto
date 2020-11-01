/**
 * 
 */
package com.example.encryption.paillier;

import cn.edu.ncepu.crypto.encryption.paillier.PaillierEngine;
import cn.edu.ncepu.crypto.encryption.paillier.PaillierProvider;
import cn.edu.ncepu.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Sep 6, 2020 11:58:19 AM
 * @ClassName PaillierPerformanceTest
 * @Description:  (performance test of the paillier cryptosystem)
 */
public class PaillierPerformanceTest {
    private static final Logger logger = LoggerFactory.getLogger(PaillierPerformanceTest.class);
    private static final String DELIMITER = "[,]";
    // file path for performance test result
    private static final String default_path = "benchmarks/encryption/paillier/";
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

    // timeMultiply time
    private double timeMultiply;

    private static PaillierEngine engine;

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
        logger.info("average keyGen time:  " + this.timeKeyGen     / test_round);
        out.println("average keyGen time:  " + this.timeKeyGen     / test_round);
        logger.info("average encrypt time: " + this.timeEncryption / test_round);
        out.println("average encrypt time: " + this.timeEncryption / test_round);
        logger.info("average decrypt time: " + this.timeDecryption / test_round);
        out.println("average decrypt time: " + this.timeDecryption / test_round);
        logger.info("average multiply time:" + this.timeMultiply   / test_round);
        out.println("average multiply time:" + this.timeMultiply   / test_round);
    }

    private void run_one_round() {
        try {
            double temperTime;
            Timer timer = new Timer();

            // test key generation performance
            out.print("KeyGen: ");
            timer.start(0);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Paillier");
            kpg.initialize(1024);
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey privKey = keyPair.getPrivate();
            temperTime = timer.stop(0);
            logger.info("KeyGen;" + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeKeyGen += temperTime;

            String plainText1 = "101";
            String plainText2 = "102";
            // get the n
            String[] keyComponents = pubKey.toString().split(DELIMITER);
            String keyComponent = "";
            for (String component : keyComponents) {
                if (component.startsWith("n")) {
                    keyComponent = component.substring(2);// ignoring 'n:' or 'r:'
                }
            }
            BigInteger n = new BigInteger(keyComponent);
            byte[] first = new BigInteger(plainText1).toByteArray();
            byte[] second = new BigInteger(plainText2).toByteArray();
            BigInteger n2 = n.multiply(n);

            final Cipher cipherHP = Cipher.getInstance("PaillierHP");
            // test encryption performance
            out.print("Encryption: ");
            timer.start(0);
            BigInteger codedBytes1 = engine.encrypt(first, pubKey, cipherHP);
            temperTime = timer.stop(0);
            logger.info("Encryption; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeEncryption += temperTime;


            BigInteger codedBytes2 = engine.encrypt(second, pubKey, cipherHP);

            // test decryption performance
            out.print("Decryption: ");
            timer.start(0);
            BigInteger resultPlain = engine.decrypt(codedBytes1.toByteArray(), privKey, cipherHP);
            temperTime = timer.stop(0);
            logger.info("Decryption; " + "\t" + temperTime);
            out.println("\t" + temperTime);
            this.timeDecryption += temperTime;

            // test multiply performance
            out.print("Multiply");
            timer.start(0);
            // product
            BigInteger product = codedBytes1.multiply(codedBytes2);
            BigInteger tallyProduct = product.mod(n2);
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
    public void testPaillierPerformance() {
        PaillierPerformanceTest performanceTest = new PaillierPerformanceTest();
        performanceTest.engine = PaillierEngine.getInstance();
        // Add dynamically the desired provider
        Security.addProvider(new PaillierProvider());
        performanceTest.runPerformanceTest();
    }
}
