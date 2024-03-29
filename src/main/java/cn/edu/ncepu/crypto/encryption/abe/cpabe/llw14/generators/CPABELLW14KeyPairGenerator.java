package cn.edu.ncepu.crypto.encryption.abe.cpabe.llw14.generators;

import org.bouncycastle.crypto.KeyGenerationParameters;

import cn.edu.ncepu.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14PublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13KeyPairGenerator;
import cn.edu.ncepu.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE public key / master secret key pair generator.
 */
public class CPABELLW14KeyPairGenerator extends CPABERW13KeyPairGenerator {
	public PairingKeySerPair generateKeyPair() {
		PairingKeySerPair pairingKeySerPair = super.generateKeyPair();
		CPABERW13PublicKeySerParameter publicKeyRW13Parameter = (CPABERW13PublicKeySerParameter) pairingKeySerPair
				.getPublic();
		CPABERW13MasterSecretKeySerParameter masterKeyRW13Parameter = (CPABERW13MasterSecretKeySerParameter) pairingKeySerPair
				.getPrivate();
		AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator = this.parameters
				.getChameleonHashKeyPairGenerator();
		KeyGenerationParameters chameleonHashKeyGenerationParameter = this.parameters
				.getChameleonHashKeyGenerationParameter();
		chameleonHashKeyPairGenerator.init(chameleonHashKeyGenerationParameter);
		AsymmetricKeySerPair keyPair = chameleonHashKeyPairGenerator.generateKeyPair();
		AsymmetricKeySerParameter chameleonHashPublicKey = keyPair.getPublic();

		CPABELLW14PublicKeySerParameter publicKeyParameter = new CPABELLW14PublicKeySerParameter(
				publicKeyRW13Parameter.getParameters(), chameleonHashPublicKey, publicKeyRW13Parameter.getG(),
				publicKeyRW13Parameter.getU(), publicKeyRW13Parameter.getH(), publicKeyRW13Parameter.getW(),
				publicKeyRW13Parameter.getV(), publicKeyRW13Parameter.getEggAlpha());
		CPABELLW14MasterSecretKeySerParameter masterKeyParameter = new CPABELLW14MasterSecretKeySerParameter(
				masterKeyRW13Parameter.getParameters(), masterKeyRW13Parameter.getAlpha());
		return new PairingKeySerPair(publicKeyParameter, masterKeyParameter);
	}
}