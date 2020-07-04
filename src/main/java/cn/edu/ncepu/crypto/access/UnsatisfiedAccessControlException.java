package cn.edu.ncepu.crypto.access;

/**
 * Created by Weiran Liu on 2016/7/18.
 *
 * Unsatisfied access control exception, used for access control policy.
 */

public class UnsatisfiedAccessControlException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4622839848943865941L;

	public UnsatisfiedAccessControlException(String message) {
		super(message);
	}
}
