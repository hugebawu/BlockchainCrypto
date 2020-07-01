package cn.edu.ncepu.crypto.encryption.hibe.bb04;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.HIBEEngine;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.generators.HIBEBB04DecryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.generators.HIBEBB04EncryptionGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.generators.HIBEBB04SecretKeyGenerator;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.serparams.HIBEBB04CiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.serparams.HIBEBB04HeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.serparams.HIBEBB04MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.bb04.serparams.HIBEBB04SecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEDelegateGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBEKeyPairGenerationParameter;
import cn.edu.ncepu.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Boneh-Boyen HIBE engine.
 */
public class HIBEBB04Engine extends HIBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Boneh-Boyen-04 HIBE scheme";

    private static HIBEBB04Engine engine;

    public static HIBEBB04Engine getInstance() {
        if (engine == null) {
            engine = new HIBEBB04Engine();
        }
        return engine;
    }

    private HIBEBB04Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
        HIBEBB04KeyPairGenerator keyPairGenerator = new HIBEBB04KeyPairGenerator();
        keyPairGenerator.init(new HIBEKeyPairGenerationParameter(pairingParameters, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String... ids) {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBEBB04PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBEBB04MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, HIBEBB04MasterSecretKeySerParameter.class.getName());
        }
        HIBEBB04SecretKeyGenerator secretKeyGenerator = new HIBEBB04SecretKeyGenerator();
        secretKeyGenerator.init(new HIBESecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id) {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBEBB04PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBB04SecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBEBB04SecretKeySerParameter.class.getName());
        }
        HIBEBB04SecretKeyGenerator secretKeyGenerator = new HIBEBB04SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEDelegateGenerationParameter(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBEBB04PublicKeySerParameter.class.getName());
        }
        HIBEBB04EncryptionGenerator encryptionGenerator = new HIBEBB04EncryptionGenerator();
        encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBEBB04PublicKeySerParameter.class.getName());
        }
        HIBEBB04EncryptionGenerator encryptionGenerator = new HIBEBB04EncryptionGenerator();
        encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBEBB04PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBB04SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBEBB04SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBEBB04CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, HIBEBB04CiphertextSerParameter.class.getName());
        }
        HIBEBB04DecryptionGenerator decryptionGenerator = new HIBEBB04DecryptionGenerator();
        decryptionGenerator.init(new HIBEDecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBEBB04PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBB04SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBEBB04SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof HIBEBB04HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, HIBEBB04HeaderSerParameter.class.getName());
        }
        HIBEBB04DecryptionGenerator decryptionGenerator = new HIBEBB04DecryptionGenerator();
        decryptionGenerator.init(new HIBEDecryptionGenerationParameter(publicKey, secretKey, ids, header));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
