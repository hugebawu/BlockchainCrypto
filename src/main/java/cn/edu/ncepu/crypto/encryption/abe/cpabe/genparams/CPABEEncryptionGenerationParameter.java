package cn.edu.ncepu.crypto.encryption.abe.cpabe.genparams;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.access.AccessControlEngine;
import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.chameleonhash.ChameleonHasher;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * CP-ABE ciphertext generation parameter.
 */
public class CPABEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
	private final AccessControlEngine accessControlEngine;
	private final int[][] accessPolicy;
	private final String[] rhos;
	private ChameleonHasher chameleonHasher;
	private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
	private KeyGenerationParameters chameleonHashKeyPairGenerationParameter;
	private PairingCipherSerParameter intermediate;

	public CPABEEncryptionGenerationParameter(AccessControlEngine accessControlEngine,
			PairingKeySerParameter publicKeyParameter, int[][] accessPolicy, String[] rhos, Element message) {
		super(publicKeyParameter, message);
		this.accessControlEngine = accessControlEngine;
		this.accessPolicy = accessPolicy;
		this.rhos = rhos;
	}

	public void setIntermediate(PairingCipherSerParameter intermediate) {
		this.intermediate = intermediate;
	}

	public void setChameleonHasher(ChameleonHasher chameleonHasher) {
		this.chameleonHasher = chameleonHasher;
	}

	public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator keyPairGenerator) {
		this.chameleonHashKeyPairGenerator = keyPairGenerator;
	}

	public void setChameleonHashKeyPairGenerationParameter(KeyGenerationParameters keyGenerationParameters) {
		this.chameleonHashKeyPairGenerationParameter = keyGenerationParameters;
	}

	public AccessControlEngine getAccessControlEngine() {
		return this.accessControlEngine;
	}

	public int[][] getAccessPolicy() {
		return this.accessPolicy;
	}

	public String[] getRhos() {
		return this.rhos;
	}

	public ChameleonHasher getChameleonHasher() {
		return this.chameleonHasher;
	}

	public boolean isIntermediateGeneration() {
		return (this.intermediate != null);
	}

	public PairingCipherSerParameter getIntermediate() {
		return this.intermediate;
	}

	public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
		return this.chameleonHashKeyPairGenerator;
	}

	public KeyGenerationParameters getChameleonHashKeyPairGenerationParameter() {
		return this.chameleonHashKeyPairGenerationParameter;
	}
}
