/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphiencryption;

import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

/**
 *
 * @版权 : Copyright (c) 2018-2019 E1101智能电网信息安全中心
 * @author: Hu Baiji
 * @E-mail: drbjhu@163.com
 * @创建日期: 2019年10月16日 下午7:35:19
 * @ClassName HE
 * @类描述-Description:  
 * @修改记录:
 * @版本: 1.0
 */
public interface HE {

	/**
	 * TODO generate system parameters
	 */
	void setup();

	/**
	 * TODO extract user secret key
	 * @param id user identity
	 * @return 
	 */
	Element extract(String id);

	/**
	 * TODO encrypt
	 * @param message
	 * @return 参数描述
	 */
	CipherText encrypt(String message);

	/**
	 * TODO  decrypt
	 * @param d user secret key
	 * @param ciphertext
	 * @return 参数描述
	 */
	String decrypt(Element d, CipherText ciphertext);

	/**
	 * TODO add method for ciphertext
	 * @param ciphertextMap map of ciphertext
	 * @return
	 */
	public CipherText add(Map<String, CipherText> ciphertextMap);
}
