package cn.edu.buaa.crypto.encryption.ibe.gen06a;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.generators.IBEGen06aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.generators.IBEGen06aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.generators.IBEGen06aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.generators.IBEGen06aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.*;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry IBE engine.
 */
public class IBEGen06aEngine extends IBEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Gentry-06 CPA-secure IBE";

    private static IBEGen06aEngine engine;

    public static IBEGen06aEngine getInstance() {
        if (engine == null) {
            engine = new IBEGen06aEngine();
        }
        return engine;
    }

    private IBEGen06aEngine() { super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.ANON); }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        IBEGen06aKeyPairGenerator keyPairGenerator = new IBEGen06aKeyPairGenerator();
        keyPairGenerator.init(new IBEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof IBEGen06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEGen06aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof IBEGen06aMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, IBEGen06aMasterSecretKeySerParameter.class.getName());
        }
        IBEGen06aSecretKeyGenerator secretKeyGenerator = new IBEGen06aSecretKeyGenerator();
        secretKeyGenerator.init(new IBESecretKeyGenerationParameter(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id){
        if (!(publicKey instanceof IBEGen06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEGen06aPublicKeySerParameter.class.getName());
        }
        IBEGen06aEncryptionGenerator encryptionGenerator = new IBEGen06aEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String id, Element message){
        if (!(publicKey instanceof IBEGen06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEGen06aPublicKeySerParameter.class.getName());
        }
        IBEGen06aEncryptionGenerator encryptionGenerator = new IBEGen06aEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String id, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEGen06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEGen06aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEGen06aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, IBEGen06aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof IBEGen06aCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, IBEGen06aCiphertextSerParameter.class.getName());
        }
        IBEGen06aDecryptionGenerator decryptionGenerator = new IBEGen06aDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String id, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEGen06aPublicKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEGen06aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEGen06aSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, IBEGen06aSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof IBEGen06aHeaderSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, IBEGen06aHeaderSerParameter.class.getName());
        }
        IBEGen06aDecryptionGenerator decryptionGenerator = new IBEGen06aDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, header));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
