package com.example.homomorphicencryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/21 9:17
 */

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.homomorphicEncryption.bgn.BGNEngine;
import cn.edu.ncepu.crypto.homomorphicEncryption.bgn.BGNPrivateKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.bgn.BGNPublicKeySerParameter;
import cn.edu.ncepu.crypto.utils.CommonUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        try {
            PairingParameters typeA1Parameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a1_2_256);
            BGNEngine bgnEngine = BGNEngine.getInstance();
            //keyGen
            PairingKeySerPair keyPair = bgnEngine.keyGen(typeA1Parameters);
            BGNPublicKeySerParameter publicKey = (BGNPublicKeySerParameter) keyPair.getPublic();
            BGNPrivateKeySerParameter privateKey = (BGNPrivateKeySerParameter) keyPair.getPrivate();

            //test serialization and deserialization
            byte[] byteArrayPublicKey = CommonUtils.SerObject(publicKey);
            CipherParameters anPublicKey = (CipherParameters) CommonUtils.deserObject(byteArrayPublicKey);
            Assert.assertEquals(publicKey, anPublicKey);
            publicKey = (BGNPublicKeySerParameter) anPublicKey;

            byte[] byteArrayPrivateKey = CommonUtils.SerObject(privateKey);
            CipherParameters anPrivateKey = (CipherParameters) CommonUtils.deserObject(byteArrayPrivateKey);
            Assert.assertEquals(privateKey, anPrivateKey);
            privateKey = (BGNPrivateKeySerParameter) anPrivateKey;

            // encrypt
            int m = 100;
            Element c = bgnEngine.encrypt(m, publicKey);
            // decrypt
            int decrypted_m = bgnEngine.decrypt(c, privateKey);
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
        try {
            PairingParameters typeA1Parameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a1_2_256);
            BGNEngine bgnEngine = BGNEngine.getInstance();

            //keyGen
            PairingKeySerPair keyPair = bgnEngine.keyGen(typeA1Parameters);
            BGNPublicKeySerParameter publicKey = (BGNPublicKeySerParameter) keyPair.getPublic();
            BGNPrivateKeySerParameter privateKey = (BGNPrivateKeySerParameter) keyPair.getPrivate();

            int m1 = 20, m2 = 30, m3 = 40;
            Element c1 = bgnEngine.encrypt(m1, publicKey);
            Element c2 = bgnEngine.encrypt(m2, publicKey);
            Element c3 = bgnEngine.encrypt(m3, publicKey);

            Element c1mulc2mulc3 = bgnEngine.add(c3, bgnEngine.add(c1, c2));
            int decrypted_m1plusm2plus3 = bgnEngine.decrypt(c1mulc2mulc3, privateKey);
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
        try {
            PairingParameters typeA1Parameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a1_2_256);
            BGNEngine bgnEngine = BGNEngine.getInstance();

            //keyGen
            PairingKeySerPair keyPair = bgnEngine.keyGen(typeA1Parameters);
            BGNPublicKeySerParameter publicKey = (BGNPublicKeySerParameter) keyPair.getPublic();
            BGNPrivateKeySerParameter privateKey = (BGNPrivateKeySerParameter) keyPair.getPrivate();

            int m1 = 3, m2 = 33;
            Element c1 = bgnEngine.encrypt(m1, publicKey);
            Element c1expm2 = bgnEngine.mul1(c1, m2, publicKey);
            int decrypted_c1expm2 = bgnEngine.decrypt(c1expm2, privateKey);
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
        try {
            PairingParameters typeA1Parameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a1_2_256);
            BGNEngine bgnEngine = BGNEngine.getInstance();

            //keyGen
            PairingKeySerPair keyPair = bgnEngine.keyGen(typeA1Parameters);
            BGNPublicKeySerParameter publicKey = (BGNPublicKeySerParameter) keyPair.getPublic();
            BGNPrivateKeySerParameter privateKey = (BGNPrivateKeySerParameter) keyPair.getPrivate();
            int m1 = 2, m2 = 33;
            Element c1 = bgnEngine.encrypt(m1, publicKey);
            Element c2 = bgnEngine.encrypt(m2, publicKey);
            Element c1_pairing_c2 = bgnEngine.mul2(c1, c2, publicKey);
            int decrypted_c1_pairing_c2 = bgnEngine.decrypt_mul2(c1_pairing_c2, privateKey);
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
        try {
            PairingParameters typeA1Parameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a1_2_256);
            BGNEngine bgnEngine = BGNEngine.getInstance();
            //keyGen
            PairingKeySerPair keyPair = bgnEngine.keyGen(typeA1Parameters);
            BGNPublicKeySerParameter publicKey = (BGNPublicKeySerParameter) keyPair.getPublic();
            BGNPrivateKeySerParameter privateKey = (BGNPrivateKeySerParameter) keyPair.getPrivate();
            int m = 88;
            Element c = bgnEngine.encrypt(m, publicKey);
            Element c_selfblind = bgnEngine.selfBlind(c, publicKey);
            int decrypted_c_selfblind = bgnEngine.decrypt(c_selfblind, privateKey);
            assertTrue(decrypted_c_selfblind == m);
            logger.info("Homomorphic self-blinding tests successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getLocalizedMessage());
        }
    }

}
