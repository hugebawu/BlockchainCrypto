/**
 * 
 */
package cn.edu.ncepu.crypto.HE.ibeHE;

import java.math.BigInteger;

import org.bouncycastle.crypto.InvalidCipherTextException;

import cn.edu.ncepu.crypto.algebra.Engine;
import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jul 6, 2020 10:18:58 PM
 * @ClassName IBEHEEngine
 * @Description: TODO(This interface is an abstract of IBE based homomorphic encryption definitions)
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
	 * TODO Setup Algorithm for IBEHE
	 * @param pairingParameters: pairing parameters
	 * @return public key(P, Ppub) / master secret key(s) pair of the system
	 */
	protected abstract PairingKeySerPair setup(PairingParameters pairingParameters);

	/**
	 * TODO extract user secret key frome user id for IBEHE
	 * @param id user id
	 * @param masterKey system master key (s)
	 * @return user secret key associated with the identity id
	 */
	protected abstract PairingKeySerParameter extract(String id, PairingKeySerParameter masterKey);

	/**
	 * Encryption Algorithm for IBE
	 * @param publicKey public key
	 * @param id an identity
	 * @param message the message in GT
	 * @return ciphertext associated with the identity id
	 */

	/**
	 * TODO Homomorphic encryption algorithm for IBEHE
	 * IBE(Num1) + IBE(Num2)+ ... + IBE(Num3) = IBE(Num1+Num2+...+Numn)
	 * @param id the user id of message receiver
	 * @param publicKey system public key (P, Ppub)
	 * @param message the message waited to be homomorphic encrypted and added to send to receiver
	 * @return the cipher text (U,V) of added num associated with the receiver id
	 */
	protected abstract PairingCipherSerParameter encrypt(String id, PairingKeySerParameter publicKey,
			BigInteger biMessage) throws InvalidCipherTextException;

	/**
	 * Decryption Algorithm for IBE
	 * @param publicKey public key
	 * @param secretKey secret key associated with an identity
	 * @param id identity associating with the ciphertext
	 * @param ciphertext ciphertext
	 * @return the message in GT
	 * @throws InvalidCipherTextException if the decryption procedure is failure
	 */

	/**
	 * TODO decrypt the homomorphic encryption result
	 * @param secretKey message receiver secret key
	 * @param ciphertext IBE ciphertext (U,V)
	 * @return added Num (Num1+Num2+...+Numn)
	 */
	protected abstract BigInteger decrypt(PairingKeySerParameter secretKey, PairingCipherSerParameter ciphertext)
			throws InvalidCipherTextException;
}
