package cn.edu.buaa.crypto.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE.
 */
public class HIBBELLW16aEngine extends HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Liu-Liu-Wu-16 CPA-secure prime-order HIBBE";

    private static HIBBELLW16aEngine engine;

    public static HIBBELLW16aEngine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW16aEngine();
        }
        return engine;
    }

    private HIBBELLW16aEngine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW16aKeyPairGenerator keyPairGenerator = new HIBBELLW16aKeyPairGenerator();
        keyPairGenerator.init(new HIBBEKeyPairGenerationParameter(pairingParameters, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW16aMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, HIBBELLW16aMasterSecretKeySerParameter.class.getName());
        }
        HIBBELLW16aSecretKeyGenerator secretKeyGenerator = new HIBBELLW16aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBESecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16aSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBBELLW16aSecretKeySerParameter.class.getName());
        }
        HIBBELLW16aSecretKeyGenerator secretKeyGenerator = new HIBBELLW16aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBEDelegateGenerationParameter(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        HIBBELLW16aEncryptionGenerator encryptionGenerator = new HIBBELLW16aEncryptionGenerator();
        encryptionGenerator.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        HIBBELLW16aEncryptionGenerator encryptionGenerator = new HIBBELLW16aEncryptionGenerator();
        encryptionGenerator.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBBELLW16aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW16aCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, HIBBELLW16aCiphertextSerParameter.class.getName());
        }
        HIBBELLW16aDecryptionGenerator decryptionGenerator = new HIBBELLW16aDecryptionGenerator();
        decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, HIBBELLW16aSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof HIBBELLW16aHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, HIBBELLW16aHeaderSerParameter.class.getName());
        }
        HIBBELLW16aDecryptionGenerator decryptionGenerator = new HIBBELLW16aDecryptionGenerator();
        decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(
                publicKey, secretKey, ids, header));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
