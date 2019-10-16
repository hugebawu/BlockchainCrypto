/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.wp_ibe;

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
public interface Ident {

	void buildSystem();

	void extractSecretKey();

	void encrypt();

	void decrypt();
}
