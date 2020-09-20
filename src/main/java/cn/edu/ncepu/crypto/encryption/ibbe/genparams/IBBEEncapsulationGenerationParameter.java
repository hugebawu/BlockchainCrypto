package cn.edu.ncepu.crypto.encryption.ibbe.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE encapsulation generation parameter.
 */
public class IBBEEncapsulationGenerationParameter extends PairingEncapsulationGenerationParameter {
	private final String[] ids;

	public IBBEEncapsulationGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids) {
		super(publicKeyParameter);
		this.ids = PairingUtils.removeDuplicates(ids);
	}

	public String[] getIds() {
		return this.ids;
	}

	public String getIdAt(int index) {
		return ids[index];
	}

	public int getLength() {
		return this.ids.length;
	}
}
