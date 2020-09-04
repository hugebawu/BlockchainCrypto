package cn.edu.ncepu.crypto.encryption.paillier;

import java.security.Provider;

/**
 * In addition to registering implementations of cryptographic services, the
 * Provider class can also be used to register implementations of other security
 * services that might get defined as part of the JDK Security API or one of its
 * extensions JCA ,JCE. In this case the PaillierProvider registered the
 * implementation of the PaillierKeyPairGenerator,PaillierCipher and
 * PaillierHomomorphicCipher.
 * 
 * @version 12-03-13
 * 
 */
public class PaillierProvider extends Provider {

	/**
	 * 
	 */
	private static final long serialVersionUID = 529434075782517015L;

	public PaillierProvider() {
		super("Paillier", 1.0, "Paillier's Cryptography Provider");
		/**
		 * Key Pair Generator engine
		 */
		put("KeyPairGenerator.Paillier", "cn.edu.ncepu.crypto.encryption.paillier.PaillierKeyPairGenerator");
		/**
		 * Cipher engine for homomorphic operations
		 */
		put("Cipher.PaillierHP", "cn.edu.ncepu.crypto.encryption.paillier.PaillierHomomorphicCipher");
		/**
		 * Cipher engine
		 */
		put("Cipher.Paillier", "cn.edu.ncepu.crypto.encryption.paillier.PaillierCipher");

	}

}
