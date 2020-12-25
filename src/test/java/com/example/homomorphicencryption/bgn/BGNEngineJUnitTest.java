package com.example.homomorphicencryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/21 9:17
 */

import cn.edu.ncepu.crypto.homomorphicEncryption.bgn.BGNEngine;
import cn.edu.ncepu.crypto.homomorphicEncryption.bgn.BGNKeyPairGenerator;
import cn.edu.ncepu.crypto.homomorphicEncryption.bgn.BGNPrivateKey;
import cn.edu.ncepu.crypto.homomorphicEncryption.bgn.BGNPublicKey;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertTrue;

/**
 * @ClassName BNGEngineJUnitTest
 * @Description test encryption,decryption and several hommomorphism properties including addition, multiplication and self-blinding
 * @Author Administrator
 * @Date 2020/12/21 9:17
 * @Version 1.0
 **/
public class BGNEngineJUnitTest {
    private static final Logger logger = LoggerFactory.getLogger(BGNEngineJUnitTest.class);

    @Test
    public void testEnc_Decryption() throws NoSuchAlgorithmException {
        BGNEngine bgnEngine = BGNEngine.getInstance();
        BGNKeyPairGenerator kpg = new BGNKeyPairGenerator();
        kpg.initialize(64, null);
        KeyPair keyPair = kpg.generateKeyPair();
        BGNPublicKey publicKey = (BGNPublicKey) keyPair.getPublic();
        BGNPrivateKey privateKey = (BGNPrivateKey) keyPair.getPrivate();
        try {
            int m = 100;
            Element c = bgnEngine.encrypt(m, publicKey);
            int decrypted_m = bgnEngine.decrypt(c, publicKey, privateKey);
            logger.info("decrypted_m: " + decrypted_m);
            assertTrue(decrypted_m == m);
            logger.info("Encryption and Decryption test successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }

    /*
     * @description: utilize c1*c2 to calculate m1+m2
     * @return: void
     **/
    @Test
    public void testAddHomomorphism() {
        BGNEngine bgnEngine = BGNEngine.getInstance();
        BGNKeyPairGenerator kpg = new BGNKeyPairGenerator();
        kpg.initialize(64, null);
        KeyPair keyPair = kpg.generateKeyPair();
        BGNPublicKey publicKey = (BGNPublicKey) keyPair.getPublic();
        BGNPrivateKey privateKey = (BGNPrivateKey) keyPair.getPrivate();
        try {
            int m1 = 20, m2 = 30, m3 = 40;
            Element c1 = bgnEngine.encrypt(m1, publicKey);
            Element c2 = bgnEngine.encrypt(m2, publicKey);
            Element c3 = bgnEngine.encrypt(m3, publicKey);

            Element c1mulc2mulc3 = bgnEngine.add(c3, bgnEngine.add(c1, c2));
            int decrypted_m1plusm2plus3 = bgnEngine.decrypt(c1mulc2mulc3, publicKey, privateKey);
            logger.info("decrypted_m1plusm2plus3: " + decrypted_m1plusm2plus3);
            assertTrue(decrypted_m1plusm2plus3 == (m1 + m2 + m3));
            logger.info("Homomorphic addition tests successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }

    /*
     * @description: utilize c1^m2 to calculate m1*m2
     * @return: void
     **/
    @Test
    public void testMul1Homomorphism() {
        BGNEngine bgnEngine = BGNEngine.getInstance();
        BGNKeyPairGenerator kpg = new BGNKeyPairGenerator();
        kpg.initialize(64, null);
        KeyPair keyPair = kpg.generateKeyPair();
        BGNPublicKey publicKey = (BGNPublicKey) keyPair.getPublic();
        BGNPrivateKey privateKey = (BGNPrivateKey) keyPair.getPrivate();
        try {
            int m1 = 3, m2 = 33;
            Element c1 = bgnEngine.encrypt(m1, publicKey);
            Element c1expm2 = bgnEngine.mul1(c1, m2);
            int decrypted_c1expm2 = bgnEngine.decrypt(c1expm2, publicKey, privateKey);
            logger.info("decrypted_c1expm2: " + decrypted_c1expm2);
            assertTrue(decrypted_c1expm2 == (m1 * m2));
            logger.info("Homomorphic multiplication-1 tests successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }

    /*
     * @description: utilize e(c1,c2) to calculate m1*m2
     * @return: void
     **/
    @Test
    public void testMul2Homomorphism() {
        BGNEngine bgnEngine = BGNEngine.getInstance();
        BGNKeyPairGenerator kpg = new BGNKeyPairGenerator();
        kpg.initialize(64, null);
        KeyPair keyPair = kpg.generateKeyPair();
        BGNPublicKey publicKey = (BGNPublicKey) keyPair.getPublic();
        BGNPrivateKey privateKey = (BGNPrivateKey) keyPair.getPrivate();
        try {
            int m1 = 2, m2 = 33;
            Element c1 = bgnEngine.encrypt(m1, publicKey);
            Element c2 = bgnEngine.encrypt(m2, publicKey);
            Element c1_pairing_c2 = bgnEngine.mul2(c1, c2, publicKey);
            int decrypted_c1_pairing_c2 = bgnEngine.decrypt_mul2(c1_pairing_c2, publicKey, privateKey);
            logger.info("decrypted_c1_pairing_c2: " + decrypted_c1_pairing_c2);
            assertTrue(decrypted_c1_pairing_c2 == (m1 * m2));
            logger.info("Homomorphic multiplication-2 tests successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }

    /*
     * @description: test that c * h^r does not influence the decryption of m
     * @return: void
     **/
    @Test
    public void testSelfBlinding() {
        BGNEngine bgnEngine = BGNEngine.getInstance();
        BGNKeyPairGenerator kpg = new BGNKeyPairGenerator();
        kpg.initialize(64, null);
        KeyPair keyPair = kpg.generateKeyPair();
        BGNPublicKey publicKey = (BGNPublicKey) keyPair.getPublic();
        BGNPrivateKey privateKey = (BGNPrivateKey) keyPair.getPrivate();
        try {
            int m = 88;
            BigInteger r = publicKey.getPairing().getZr().newRandomElement().toBigInteger();
            Element c = bgnEngine.encrypt(m, publicKey);
            Element c_selfblind = bgnEngine.selfBlind(c, r, publicKey);
            int decrypted_c_selfblind = bgnEngine.decrypt(c_selfblind, publicKey, privateKey);
            logger.info("decrypted_c_selfblind: " + decrypted_c_selfblind);
            assertTrue(decrypted_c_selfblind == m);
            logger.info("Homomorphic self-blinding tests successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }

}
