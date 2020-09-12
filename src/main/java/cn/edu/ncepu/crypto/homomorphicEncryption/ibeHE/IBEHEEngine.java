/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE;

import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.Engine;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jul 6, 2020 10:18:58 PM
 * @ClassName IBEHEEngine
 * @Description:  (This interface is an abstract of IBE based additive homomorphic encryption definitions)
 */
public abstract class IBEHEEngine extends Engine {

	/**
	 * Setup Algorithm for IBE
	 * @param pairingParameters pairingParameters
	 * @return public key / master secret key pair of the scheme
	 */

	/**
	 * @param schemeName
	 * @param proveSecModel
	 * @param payloadSecLevel
	 * @param predicateSecLevel
	 */
	public IBEHEEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel,
			PredicateSecLevel predicateSecLevel) {
		super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
	}

	/** 
	 *   Setup Algorithm for IBEHE
	 * @param pairingParameters: pairing parameters
	 * @return public key(P, Ppub) / master secret key(s) pair of the system
	 */
	public abstract PairingKeySerPair setup(PairingParameters pairingParameters);

	/**
	 *   extract user secret key frome user id for IBEHE
	 * @param id user id
	 * @param masterKey system master key (s)
	 * @return user secret key associated with the identity id
	 */
	public abstract PairingKeySerParameter extract(String id, PairingKeySerParameter masterKey);

	/**
	 * Encryption Algorithm for IBE
	 * @param publicKey public key
	 * @param id an identity
	 * @param message the message in GT
	 * @return ciphertext associated with the identity id
	 */

	/**
	 *   Homomorphic encryption algorithm for IBEHE
	 * @param id user identity associating with the ciphertext
	 * @param publicKey system public key (P, Ppub)
	 * @param message the message waited to be homomorphic encrypted and added to send to receiver
	 * @return the cipher text (U,V) associated with the receiver id
	 */
	public abstract PairingCipherSerParameter encrypt(PairingKeySerParameter publicKey, String id, Element message);

	/**
	 *   decrypt the homomorphic encryption result
	 * @param secretKey message receiver secret key
	 * @param id user identity associating with the ciphertext
	 * @param ciphertext IBEHE ciphertext (U,V)
	 * @return the message in GT
	 * @throws InvalidCipherTextException if the decryption procedure is failure
	 */
	public abstract Element decrypt(PairingKeySerParameter secretKey, String id, PairingCipherSerParameter ciphertext)
			throws InvalidCipherTextException;

	/**
	 *   the add method of the IBE-based additive homomorphic encryption
	 * @param publicKey system public key
	 * @param ciphertextMap list of 
	 * @return added chiphertext
	 */
	public abstract PairingCipherSerParameter add(PairingKeySerParameter publicKey,
			Map<String, PairingCipherSerParameter> ciphertextMap);
}
