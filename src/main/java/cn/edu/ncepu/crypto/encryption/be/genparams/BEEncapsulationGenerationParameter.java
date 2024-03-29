package cn.edu.ncepu.crypto.encryption.be.genparams;

import cn.edu.ncepu.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * BE key encapsulation generation parameter.
 */
public class BEEncapsulationGenerationParameter extends PairingEncapsulationGenerationParameter {
	private final int[] indexSet;

	public BEEncapsulationGenerationParameter(PairingKeySerParameter publicKeyParameter, int[] indexSet) {
		super(publicKeyParameter);
		this.indexSet = PairingUtils.removeDuplicates(indexSet);
	}

	public int[] getIndexSet() {
		return this.indexSet;
	}
}
