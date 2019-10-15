package cn.edu.buaa.crypto.encryption.abe.kpabe;

import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.sepe.SelfExtractableBaseEngine;
import cn.edu.buaa.crypto.encryption.sepe.serparams.SEPEHeaderParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Self-extractable ABE engine.
 */
public class SelfExtractableKPABEEngine extends Engine {
    private final KPABEEngine engine;
    private final SelfExtractableBaseEngine selfExtractableBaseEngine;

    public SelfExtractableKPABEEngine(KPABEEngine engine, PBEParametersGenerator pbeParametersGenerator, BlockCipher blockCipher, Digest digest) {
        super(engine.getEngineName(), engine.getProveSecModel(), engine.getPayloadSecLevel(), engine.getPredicateSecLevel());
        this.engine = engine;
        this.selfExtractableBaseEngine = new SelfExtractableBaseEngine(engine, pbeParametersGenerator, blockCipher, digest);
    }

    public boolean isSupportIntermediate() {
        return (this.engine instanceof OOKPABEEngine);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributeNum) {
        return engine.setup(pairingParameters, maxAttributeNum);
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String accessPolicy) throws PolicySyntaxException {
        return engine.keyGen(publicKey, masterKey, accessPolicy);
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        return engine.keyGen(publicKey, masterKey, accessPolicyIntArrays, rhos);
    }

    public byte[] selfKeyGen() {
        return this.selfExtractableBaseEngine.selfKeyGen();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(this.engine instanceof OOKPABEEngine)) {
            throw new IllegalArgumentException("Engine does not support online/offline mechanism");
        }
        OOKPABEEngine ooEngine = (OOKPABEEngine)this.engine;
        return ooEngine.offlineEncryption(publicKey, n);
    }

    public PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            String[] attributes, byte[] ek) {
        if (!(this.engine instanceof OOKPABEEngine)) {
            throw new IllegalArgumentException("Engine does not support online/offline mechanism");
        }
        OOKPABEEngine ooEngine = (OOKPABEEngine)this.engine;
        PairingKeyEncapsulationSerPair encapsulationPair = ooEngine.encapsulation(publicKey, intermediate, attributes);
        return this.selfExtractableBaseEngine.encapsulation(encapsulationPair, ek);
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes, byte[] ek){
        PairingKeyEncapsulationSerPair encapsulationPair = this.engine.encapsulation(publicKey, attributes);
        return this.selfExtractableBaseEngine.encapsulation(encapsulationPair, ek);
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String[] attributes, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(header instanceof SEPEHeaderParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(this.selfExtractableBaseEngine.getEngineName(), header, SEPEHeaderParameter.class.getName());
        }
        SEPEHeaderParameter seHeaderParameter = (SEPEHeaderParameter)header;
        PairingCipherSerParameter headerParameter = seHeaderParameter.getCtY();
        byte[] ct_k = seHeaderParameter.getCtK();
        byte[] k_prime_temp = this.engine.decapsulation(publicKey, secretKey, attributes, headerParameter);
        return this.selfExtractableBaseEngine.decapsulation(k_prime_temp, ct_k);
    }

    public byte[] selfDecapsulation(byte[] ek, PairingCipherSerParameter header) throws InvalidCipherTextException {
        return this.selfExtractableBaseEngine.selfDecapsulation(ek, header);
    }

    public String getEngineName() {
        return this.selfExtractableBaseEngine.getEngineName();
    }

    public boolean isAccessControlEngineSupportThresholdGate() {
        return this.engine.isAccessControlEngineSupportThresholdGate();
    }
}
