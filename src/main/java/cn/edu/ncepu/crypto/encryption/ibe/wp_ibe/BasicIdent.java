/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.ibe.wp_ibe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 *
 * @版权 : Copyright (c) 2018-2019 E1101智能电网信息安全中心
 * @author: Hu Baiji
 * @E-mail: drbjhu@163.com
 * @创建日期: 2019年10月16日 下午7:37:14
 * @ClassName BasicIdent2
 * @类描述-Description:  这个类是核心类，包括初始化init()，配对的对称性判断checkSymmetric()，
 * 系统建立buildSystem()，密钥提取extractSecretKey()，加密encrypt()，解密decrypt()。
 * @修改记录:
 * @版本: 1.0
 */

public class BasicIdent implements Ident {
	private static Logger logger = LoggerFactory.getLogger(BasicIdent.class);

	private Element s, r, P, Ppub, Su, Qu, V, T1, T2;
	private Field G1, Zr;
	private Pairing pairing;

	public BasicIdent(Pairing pairing) {
		this.pairing = pairing;
		init();
	}

	/**
	 * 初始化
	 * @return void 
	 */
	private void init() {
		// For bilinear maps only, to use the PBC wrapper and gain in performance, the
		// usePBCWhenPossible property of the pairing factory must be set.
		// Moreover, if PBC and the JPBC wrapper are not installed properly then the
		// factory will resort to the JPBC pairing implementation.
		// 需要配置才能使用http://gas.dia.unisa.it/projects/jpbc/docs/pbcwrapper.html#.XvnxeygzZPY
		PairingFactory.getInstance().setUsePBCWhenPossible(true);//
		checkSymmetric(pairing);
		// 将变量r初始化为Zr中的元素
		Zr = pairing.getZr();
		r = Zr.newElement();
		// 将变量Ppub，Qu，Su，V初始化为G1中的元素，G1是加法群
		G1 = pairing.getG1();
		Ppub = G1.newElement();
		Qu = G1.newElement();
		Su = G1.newElement();
		V = G1.newElement();
		// 将变量T1，T2V初始化为GT中的元素，GT是乘法群
		Field GT = pairing.getGT();
		T1 = GT.newElement();
		T2 = GT.newElement();
	}

	/**
	 * 判断配对是否为对称配对，不对称则输出错误信息
	 * @param pairing 
	 * @return void  
	 */
	private void checkSymmetric(Pairing pairing) {
		if (!pairing.isSymmetric()) {
			throw new RuntimeException("密钥不对称!");
		}
	}

	@Override
	public void buildSystem() {
		logger.info("-------------------系统建立阶段----------------------");
		s = Zr.newRandomElement().getImmutable();// //随机生成主密钥s
		P = G1.newRandomElement().getImmutable();// 生成G1的生成元P
		Ppub = P.mulZn(s);// 计算Ppub=sP,注意顺序
		logger.info("P=" + P);
		logger.info("s=" + s);
		logger.info("Ppub=" + Ppub);
	}

	@Override
	public void extractSecretKey() {
		logger.info("-------------------密钥提取阶段----------------------");
		Qu = pairing.getG1().newElement().setFromHash("IDu".getBytes(), 0, 3).getImmutable();// //从长度为3的Hash值IDu确定用户U产生的公钥Qu
		Su = Qu.mulZn(s).getImmutable();
		logger.info("Qu=" + Qu);
		logger.info("Su=" + Su);
	}

	@Override
	public void encrypt() {
		logger.info("-------------------加密阶段----------------------");
		r = Zr.newRandomElement().getImmutable();
		V = P.mulZn(r);
		T1 = pairing.pairing(Ppub, Qu).getImmutable();// 计算e（Ppub,Qu）
		T1 = T1.powZn(r).getImmutable();
		logger.info("r=" + r);
		logger.info("V=" + V);
		logger.info("T1=e（Ppub,Qu）^r=" + T1);
	}

	@Override
	public void decrypt() {
		logger.info("-------------------解密阶段----------------------");
		T2 = pairing.pairing(V, Su).getImmutable();
		logger.info("e(V,Su)=" + T2);
		int byt = V.getLengthInBytes();// 求V的字节长度，假设消息长度为128字节
		logger.info("文本长度" + (byt + 128));
	}
}
