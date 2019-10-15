package com.example.encryption.re;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import cn.edu.buaa.crypto.encryption.re.REEngine;
import cn.edu.buaa.crypto.encryption.re.llw16a.OORELLW16aEngine;
import cn.edu.buaa.crypto.encryption.re.llw16b.OORELLW16bEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Assert;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption engine test.
 */
public class REEngineJUnitTest extends TestCase {
    private static final String identity = "ID";
    private static final String identityRevoke = "RevokeID";

    private static final String[] identityRevokeSet1 = {"ID_1", "RevokeID"};
    private static final String[] identityRevokeSet2 = {"RevokeID", "ID_1"};
    private static final String[] identityRevokeSet3 = {"ID_1", "ID_2", "ID_3", "ID_4", "RevokeID", "ID_5", "ID_6", "ID_7", "ID_8", "ID_9"};
    private static final String[] identityRevokeSet4 = {"ID_2", "ID_2", "ID_2", "ID_3", "RevokeID", "ID_5", "ID_5", "ID_5", "ID_5", "ID_9"};

    private REEngine engine;

    private void try_valid_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                       String identity, String[] identityRevokeSet) {
        try {
            try_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet);
        } catch (Exception e) {
            System.out.println("Valid decryption test failed, " +
                    "identity for secret key  = " + identity + ", " +
                    "ciphertext revoke ID set = " + Arrays.toString(identityRevokeSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_invalid_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         String identity, String[] identityRevokeSet) {
        try {
            try_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid decryption test failed, " +
                    "identity for secret key  = " + identity + ", " +
                    "ciphertext revoke ID set = " + Arrays.toString(identityRevokeSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                 String identity, String[] identityRevokeSet)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identity);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityRevokeSet, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, identityRevokeSet, ciphertext);
        Assert.assertEquals(message, anMessage);

        //Encapsulation and serialization
        PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityRevokeSet);
        byte[] sessionKey = encapsulationPair.getSessionKey();
        PairingCipherSerParameter header = encapsulationPair.getHeader();
        byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
        CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
        Assert.assertEquals(header, anHeader);
        header = (PairingCipherSerParameter)anHeader;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityRevokeSet, header);
        Assert.assertArrayEquals(sessionKey, anSessionKey);

        if (this.engine instanceof OOREEngine) {
            OOREEngine ooEngine = (OOREEngine)this.engine;
            //offline encryption and serialization
            PairingCipherSerParameter intermediate = ooEngine.offlineEncryption(publicKey, PairingUtils.removeDuplicates(identityRevokeSet).length);
            byte[] byteArrayIntermediate = TestUtils.SerCipherParameter(intermediate);
            CipherParameters anIntermediate = TestUtils.deserCipherParameters(byteArrayIntermediate);
            Assert.assertEquals(intermediate, anIntermediate);
            intermediate = (PairingCipherSerParameter)anIntermediate;

            //Encryption and serialization
            ciphertext = ooEngine.encryption(publicKey, intermediate, identityRevokeSet, message);
            byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            anMessage = engine.decryption(publicKey, secretKey, identityRevokeSet, ciphertext);
            Assert.assertEquals(message, anMessage);

            //Encapsulation and serialization
            encapsulationPair = ooEngine.encapsulation(publicKey, intermediate, identityRevokeSet);
            sessionKey = encapsulationPair.getSessionKey();
            header = encapsulationPair.getHeader();
            byteArrayHeader = TestUtils.SerCipherParameter(header);
            anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
            Assert.assertEquals(header, anHeader);
            header = (PairingCipherSerParameter)anHeader;

            //Decapsulation
            anSessionKey = engine.decapsulation(publicKey, secretKey, identityRevokeSet, header);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        }
    }

    private void runAllTest(PairingParameters pairingParameters) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        try {
            // Setup and serialization
            PairingKeySerPair keyPair = engine.setup(pairingParameters);
            PairingKeySerParameter publicKey = keyPair.getPublic();
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            Assert.assertEquals(publicKey, anPublicKey);
            publicKey = (PairingKeySerParameter) anPublicKey;

            PairingKeySerParameter masterKey = keyPair.getPrivate();
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            Assert.assertEquals(masterKey, anMasterKey);
            masterKey = (PairingKeySerParameter) anMasterKey;

            //test valid example
            System.out.println("Test valid examples");
            try_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet1);
            try_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet2);
            try_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet3);
            try_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet4);

            //test invalid example
            System.out.println("Test invalid examples");
            try_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet1);
            try_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet2);
            try_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet3);
            try_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet4);
            System.out.println(engine.getEngineName() + " test passed");
        } catch (ClassNotFoundException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        } catch (IOException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void testRELSW10aEngine() {
        this.engine = RELSW10aEngine.getInstance();
        runAllTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testRELLW16aEngine() {
        this.engine = OORELLW16aEngine.getInstance();
        runAllTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testRELLW16bEngine() {
        this.engine = OORELLW16bEngine.getInstance();
        ChameleonHasher chameleonHasher  = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()), new SHA256Digest());
        AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
        KeyGenerationParameters keyGenerationParameters = new DLogKR00bKeyGenerationParameters(new SecureRandom(),
                SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);
        ((OORELLW16bEngine)this.engine).setChameleonHasher(chameleonHasher, chKeyPairGenerator, keyGenerationParameters);
        runAllTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}
