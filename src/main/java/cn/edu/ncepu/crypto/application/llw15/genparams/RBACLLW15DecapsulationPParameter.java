package cn.edu.ncepu.crypto.application.llw15.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu role-based access control patient's session key decapsulation parameter.
 */
public class RBACLLW15DecapsulationPParameter extends PairingDecryptionGenerationParameter {
	private final String[] roles;
	private final String time;
	private final String id;

	public RBACLLW15DecapsulationPParameter(PairingKeySerParameter publicKeyParameter,
			PairingKeySerParameter accessCredentialPParameter, String id, String[] roles, String time,
			PairingCipherSerParameter encapsulationParameter) {
		super(publicKeyParameter, accessCredentialPParameter, encapsulationParameter);
		assert (roles.length == ((RBACLLW15PublicKeySerParameter) publicKeyParameter).getMaxRoleNumber());
		this.roles = roles;
		this.time = time;
		this.id = id;
	}

	public String[] getRoles() {
		return this.roles;
	}

	public String getRolesAt(int index) {
		return this.roles[index];
	}

	public String getId() {
		return this.id;
	}

	public String getTime() {
		return this.time;
	}
}