package cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.ncepu.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aCiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aHeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aSecretKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE decryption generator.
 */
public class IBEBF01aDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
	private IBEDecryptionGenerationParameter params;

	private Element sessionKey;

	@Override
	public void init(CipherParameters params) {
		this.params = (IBEDecryptionGenerationParameter) params;
	}

	private void computeDecapsulation() throws InvalidCipherTextException {
		IBEBF01aPublicKeySerParameter publicKeyParameter = (IBEBF01aPublicKeySerParameter) this.params
				.getPublicKeyParameter();
		IBEBF01aSecretKeySerParameter secretKeyParameter = (IBEBF01aSecretKeySerParameter) this.params
				.getSecretKeyParameter();
		IBEBF01aHeaderSerParameter headerParameter = (IBEBF01aHeaderSerParameter) this.params.getCiphertextParameter();
		Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
		Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(),
				PairingUtils.PairingGroupType.G1);

		if (!secretKeyParameter.getElementId().equals(elementIdCT)) {
			throw new InvalidCipherTextException(
					"Secret Key identity vector does not match Ciphertext identity vector");
		}

		this.sessionKey = PairingUtils.MapByteArrayToGroup(pairing,
				pairing.pairing(secretKeyParameter.getD(), headerParameter.getU()).toBytes(),
				PairingUtils.PairingGroupType.GT);
	}

	@Override
	public byte[] recoverKey() throws InvalidCipherTextException {
		computeDecapsulation();
		return this.sessionKey.toBytes();
	}

	@Override
	public Element recoverMessage() throws InvalidCipherTextException {
		computeDecapsulation();
		IBEBF01aCiphertextSerParameter ciphertextParameter = (IBEBF01aCiphertextSerParameter) this.params
				.getCiphertextParameter();
		return ciphertextParameter.getV().div(sessionKey).getImmutable();
	}
}
