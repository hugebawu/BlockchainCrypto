/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.ibe.wp_ibe;

import java.util.Map;

import cn.edu.ncepu.crypto.encryption.ibe.wp_ibe.BasicIBE.CipherText;
import it.unisa.dia.gas.jpbc.Element;

/**
 *
 * @版权 : Copyright (c) 2018-2019 E1101智能电网信息安全中心
 * @author: Hu Baiji
 * @E-mail: drbjhu@163.com
 * @创建日期: 2019年10月16日 下午7:35:19
 * @ClassName Ident
 * @类描述-Description:  BasicIdent的基于身份的加密体制是由Boneh和Franklin
 * 在《Identity-Based Encryption fromthe Weil Pairing》提出的，
 * 算法的加解密过程大家可以自行参考下这篇论文，过程还是比较简单的。
 * @修改记录:
 * @版本: 1.0
 */
public interface IBE {

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
	 * TODO IBE decrypt
	 * @param d user secret key
	 * @param ciphertext
	 * @return 参数描述
	 */
	String decrypt(Element d, CipherText ciphertext);

	@Deprecated
	public CipherText add(Map<String, CipherText> ciphertextMap);
}
