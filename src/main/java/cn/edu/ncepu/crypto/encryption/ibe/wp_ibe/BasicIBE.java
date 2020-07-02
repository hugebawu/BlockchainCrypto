/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.ibe.wp_ibe;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
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

public class BasicIBE implements IBE {
	private static Logger logger = LoggerFactory.getLogger(BasicIBE.class);
	// 注意，这里M不能过长，受到Fq2中q的大小限制
	private static String M = "12123464312哈哈的法阿斯顿饭阿斯顿饭s6345674444442323";
	// system parameters: params = <q,n,P,Ppub,G,H>
	private Element s, // master key
			P, // G1的生成元
			Ppub, // Ppub = sP
			Qu, // 用户公钥 Qu = MapToPoin("User ID")
			Su, // 通过用户公钥生成的用户私钥 Su = sQu
			r, // Zr中的元素
			U, // 密文的第一部分 U = rP
			T1, // T1 = e(Qu,Ppub)^r
			V, // 密文的第二部分 V = M xor T1; M 是明文. 密文: C = (U, V)
			T2; // T2 = e(Su,U) = e(sQu,rP) = e(Qu,P)^sr = e(Qu,Ppub)^r = T1; 则明文: M = V xor T2

	// G1是定义在域Fq上的椭圆曲线，其阶为r.q与r都是质数，且存在一定的关系：这里是 (q+1)=r*h
	// Zr 是阶为r的环Zr={0,...,r-1}
	// GT是有限域Fq2。其元素的阶虽然为r，但是其取值范围比q大的多，目前不清楚怎么回事。
	private Field G1, Zr, GT;
	private Pairing pairing;

	public BasicIBE(PairingParameters typeAParams) {
		this.pairing = PairingFactory.getPairing(typeAParams);
		init();
		// Create a new element with a specified value
		// r is the order of ring Zr a prime; q is the order of Filed Fq also a prime.
		BigInteger r = typeAParams.getBigInteger("r");
		logger.info("r bit length: " + r.toString(2).length());
		BigInteger q = typeAParams.getBigInteger("q");
		logger.info("q bit length: " + q.toString(2).length());
		logger.info("");
		logger.info("(q+1) mod r = " + (q.add(new BigInteger("1"))).remainder(r));
		BigInteger h = q.add(new BigInteger("1")).divide(r);
		logger.info("q: " + q);
		logger.info("r: " + r);
		logger.info("h = (q+1)/r: " + h);
		logger.info("");
		logger.info("Zr order: " + Zr.getOrder());
		logger.info("Zr order bits length: " + Zr.getOrder().bitLength());
		Element elementZr = Zr.newElement();
		Element elementZr1 = Zr.newElement(new BigInteger("539084384990328"));
		Element elementZr2 = Zr.newElement(4);
		logger.info("elementZr2 invert: " + elementZr2.invert().toString());
		logger.info("elementZr2 is quadratic residue?: " + elementZr2.isSqr());
		logger.info("" + elementZr1.sign());
		logger.info("");
		logger.info("G1 order: " + G1.getOrder());
		logger.info("G1 order bits length: " + G1.getOrder().bitLength());
		Element elementG1 = G1.newRandomElement().getImmutable();
		logger.info("");
		logger.info("GT order: " + GT.getOrder());
		logger.info("GT order bits length: " + GT.getOrder().bitLength());
		logger.info("GT bits length: " + GT.getLengthInBytes() * 8);
		Element elementGT = GT.newRandomElement();
		logger.info("elementGT: ", elementGT);
		logger.info("");
		// 方案1
		String bigNum = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
		logger.info("bigNum decimal lengh: " + bigNum.length());
		logger.info(" original bigNum: " + bigNum);
		elementGT.set(new BigInteger(bigNum));
		BigInteger bi = elementGT.toBigInteger();
		logger.info("recovered bigNum: " + bi.toString(10));
		// 方案2 由于采用setFromHash的hash方式，不可行
		try {
			byte[] bytes = bigNum.getBytes("UTF-8");
			elementGT.setFromHash(bytes, 0, bytes.length);
			byte[] bytes2 = elementGT.toBytes();
			logger.info(new String(bytes2, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		logger.info("");
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
		Ppub = G1.newElement(); // Create a new uninitialized element.
		Qu = G1.newElement();
		Su = G1.newElement();
		U = G1.newElement();
		// 将变量T1，T2V初始化为GT中的元素，GT是乘法群
		GT = pairing.getGT();
		V = GT.newElement();
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
	public void setup() {
		logger.info("-------------------系统建立阶段----------------------");
		s = Zr.newRandomElement().getImmutable();// //随机生成主密钥s
		P = G1.newRandomElement().getImmutable();// 生成G1的生成元P
		Ppub = P.mulZn(s);// 计算Ppub=sP,注意顺序
		logger.info("P=" + P);
		logger.info("s=" + s);
		logger.info("Ppub=" + Ppub);
	}

	@Override
	public void extract() {
		logger.info("-------------------密钥提取阶段----------------------");
		// 通过Hash函数G从用户IDu产生的公钥Qu
		Qu = pairing.getG1().newElementFromHash("IDu".getBytes(), 0, "IDu".getBytes().length).getImmutable();
		// 通过PGK生成用户私钥
		Su = Qu.mulZn(s).getImmutable();
		logger.info("Qu=" + Qu);
		logger.info("Su=" + Su);
	}

	@Override
	public void encrypt() {
		logger.info("-------------------加密阶段----------------------");
		r = Zr.newRandomElement().getImmutable();
		U = P.mulZn(r);
		T1 = pairing.pairing(Qu, Ppub).getImmutable();// 计算e（Ppub,Qu）
		T1 = T1.powZn(r).getImmutable();
		logger.info("plaintext: " + M);
		try {
			V = GT.newElement(new BigInteger(M.getBytes("UTF-8")).xor(T1.toBigInteger()));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		logger.info("r=" + r);
		logger.info("U=" + U);
		logger.info("T1=e（Qu, Ppub）^r=" + T1);
	}

	@Override
	public void decrypt() {
		try {
			logger.info("-------------------解密阶段----------------------");
			T2 = pairing.pairing(Su, U).getImmutable();
			logger.info("T2=e(Su, U)=" + T2);
			logger.info("");
			String decrypted_M;
			decrypted_M = new String(V.toBigInteger().xor(T2.toBigInteger()).toByteArray(), "UTF-8");
			logger.info("decrypted: " + decrypted_M);
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
