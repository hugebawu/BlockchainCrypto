package cn.edu.ncepu.crypto.encryption.ibe.bf01a.generators;

import org.bouncycastle.crypto.CipherParameters;

import cn.edu.ncepu.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.ncepu.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aCiphertextSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aHeaderSerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE encryption generator.
 */
public class IBEBF01aEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

	private IBEEncryptionGenerationParameter params;
	private IBEBF01aPublicKeySerParameter publicKeyParameter;
	private Element sessionKey;

	@Override
	public void init(CipherParameters params) {
		this.params = (IBEEncryptionGenerationParameter) params;
		this.publicKeyParameter = (IBEBF01aPublicKeySerParameter) this.params.getPublicKeyParameter();
	}

	private Element computeEncapsulation() {
		Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
		String id = this.params.getId();
		Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingGroupType.G1).getImmutable();
		Element r = pairing.getZr().newRandomElement().getImmutable();
		this.sessionKey = PairingUtils.MapByteArrayToGroup(pairing,
				pairing.pairing(elementId, publicKeyParameter.getGs()).powZn(r).toBytes(),
				PairingUtils.PairingGroupType.GT);
		return publicKeyParameter.getG().powZn(r).getImmutable();
	}

	@Override
	public PairingKeyEncapsulationSerPair generateEncryptionPair() {
		Element U = computeEncapsulation();
		return new PairingKeyEncapsulationSerPair(this.sessionKey.toBytes(),
				new IBEBF01aHeaderSerParameter(publicKeyParameter.getParameters(), U));
	}

	@Override
	public PairingCipherSerParameter generateCiphertext() {
		Element U = computeEncapsulation();
		Element V = this.params.getMessage().mul(sessionKey).getImmutable();
		return new IBEBF01aCiphertextSerParameter(publicKeyParameter.getParameters(), U, V);
	}
}