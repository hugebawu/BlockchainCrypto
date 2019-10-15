package cn.edu.buaa.crypto.encryption.hibbe.llw17;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE engine.
 */
public class HIBBELLW17Engine extends HIBBEEngine {
    public static final String SCHEME_NAME = "Liu-Liu-Wu-17 CCA2-secure composite-order HIBBE";
    private static HIBBELLW17Engine engine;

    private Digest digest = new SHA256Digest();

    public void setDigest(Digest digest) {
        this.digest = digest;
    }

    public static HIBBELLW17Engine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW17Engine();
        }
        return engine;
    }

    private HIBBELLW17Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CCA2, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW17KeyPairGenerator keyPairGenerator = new HIBBELLW17KeyPairGenerator();
        keyPairGenerator.init(new HIBBEKeyPairGenerationParameter(pairingParameters, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW17PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW17MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, HIBBELLW17MasterSecretKeySerParameter.class.getName());
        }
        HIBBELLW17SecretKeyGenerator secretKeyGenerator = new HIBBELLW17SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBESecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW17PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW17SecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBBELLW17SecretKeySerParameter.class.getName());
        }
        HIBBELLW17SecretKeyGenerator secretKeyGenerator = new HIBBELLW17SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBEDelegateGenerationParameter(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW17PublicKeySerParameter.class.getName());
        }
        HIBBELLW17EncryptionGenerator encryptionGenerator = new HIBBELLW17EncryptionGenerator();
        encryptionGenerator.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, message, digest));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW17PublicKeySerParameter.class.getName());
        }
        HIBBELLW17EncryptionGenerator encryptionGenerator = new HIBBELLW17EncryptionGenerator();
        encryptionGenerator.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, null, digest));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW17PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW17SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBBELLW17SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW17CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, HIBBELLW17CiphertextSerParameter.class.getName());
        }
        HIBBELLW17DecryptionGenerator decryptionGenerator = new HIBBELLW17DecryptionGenerator();
        decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext, digest));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW17PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW17SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBBELLW17SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof HIBBELLW17HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, HIBBELLW17HeaderSerParameter.class.getName());
        }
        HIBBELLW17DecryptionGenerator decryptionGenerator = new HIBBELLW17DecryptionGenerator();
        decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(publicKey, secretKey, ids, header, digest));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
