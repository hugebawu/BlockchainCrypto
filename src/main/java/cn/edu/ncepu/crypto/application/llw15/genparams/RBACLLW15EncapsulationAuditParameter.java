package cn.edu.ncepu.crypto.application.llw15.genparams;

import org.bouncycastle.crypto.CipherParameters;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.ncepu.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu EHR role-based access control encapsulation audit parameter.
 */
public class RBACLLW15EncapsulationAuditParameter implements CipherParameters {
	private final RBACLLW15PublicKeySerParameter publicKeyParameters;
	private final String[] roles;
	private final String id;
	private final String time;
	private final RBACLLW15EncapsulationSerParameter encapsulationParameters;

	public RBACLLW15EncapsulationAuditParameter(PairingKeySerParameter publicKeyParameters, String id, String[] roles,
			String time, PairingCipherSerParameter encapsulationParameters) {
		this.publicKeyParameters = (RBACLLW15PublicKeySerParameter) publicKeyParameters;
		assert (roles.length == this.publicKeyParameters.getMaxRoleNumber());
		this.roles = roles;
		this.id = id;
		this.time = time;
		this.encapsulationParameters = (RBACLLW15EncapsulationSerParameter) encapsulationParameters;
	}

	public RBACLLW15PublicKeySerParameter getPublicKeyParameters() {
		return this.publicKeyParameters;
	}

	public RBACLLW15EncapsulationSerParameter getCiphertextParameters() {
		return this.encapsulationParameters;
	}

	public String[] getRoles() {
		return this.roles;
	}

	public String getId() {
		return this.id;
	}

	public String getTime() {
		return this.time;
	}
}