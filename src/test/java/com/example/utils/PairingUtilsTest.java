/**
 * 
 */
package com.example.utils;

import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import cn.edu.ncepu.crypto.utils.SysProperty;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import it.unisa.dia.gas.plaf.jpbc.field.quadratic.DegreeTwoExtensionQuadraticField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeAPairing;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 5, 2020 3:13:04 PM
 * @ClassName PairingUtilsTest
 * @Description:  (test methods of PairingUtils)
 */
public class PairingUtilsTest {
	private static final Logger logger = LoggerFactory.getLogger(PairingUtilsTest.class);
	private static final String USER_DIR = SysProperty.USER_DIR;

	/**
	 * test dynamically generate and save Type A PairingParameters
	 * <p>
	 * symmetric prime-order bilinear pairing
	 */
	@Ignore
	@Test
	public void testGenTypeAPairParam() {
		int rbits = 256; // rbit是域Zr的阶r的比特长度
		int qbits = 1024; // qBit是域Fq的阶q的比特长度，G1,G2是由定义在域Fq上的椭圆曲线E上的点E(F_q)(x,y /in F_q)构成的群，
		// G1,G2的阶(即G的元素个数)为r. The order r is some prime factor of q + 1，such as q + 1 = r * h. GT is subgroup of F_q^2
		PairingParameters typeAParams = PairingUtils.genTypeAPairParam(rbits, qbits);
		// 将参数写入文件a_256_1024.properties中，使用Princeton大学封装的文件输出库
		Out out = new Out(PairingUtils.PATH_a_256_1024);
		out.println(typeAParams);
		// print Pairing parameters
		logger.info(typeAParams.toString());
		// 从文件a_256_1024.properties中读取参数初始化双线性群
		typeAParams = PairingFactory.getPairingParameters(PairingUtils.PATH_a_256_1024);
		//通过代码动态生成Pairing对象
		Pairing pairing = PairingFactory.getPairing(typeAParams);
		// The number of algebraic structures available
		logger.info("degree: j" + pairing.getDegree());
		BigInteger q = new BigInteger(typeAParams.getString("q"));
		logger.info("q bit length: " + q.toString(2).length());
		BigInteger r = typeAParams.getBigInteger("r");
		logger.info("r bit length: " + r.toString(2).length());
		BigInteger h = typeAParams.getBigInteger("h");
		logger.info("h bit length: " + h.toString(2).length());
		logger.info("(q+1) mod r = " + (q.add(new BigInteger("1"))).remainder(r));
		assertTrue(h.equals(q.add(new BigInteger("1")).divide(r)));
	}

	/**
	 *   test dynamically generate and save Type A1 PairingParameters
	 *   <p>
	 *   symmetric composite-order bilinear pairing
	 */
	@Ignore
	@Test
	public void testGenTypeA1PairParam() {
		int numPrime = 3; // numPrime是阶数N中有几个质数因子
		int bits = 128; // bit是每个质数因子的比特长度

		// Type A1涉及到的阶数很大，其参数产生的时间也比较长
		PairingParameters typeA1Params = PairingUtils.genTypeA1PairParam(numPrime, bits);
		// 将参数写入文件a_80_256.properties中，使用Princeton大学封装的文件输出库
		Out out = new Out(PairingUtils.PATH_a1_3_128);
		out.println(typeA1Params);
		// print Pairing parameters
		logger.info(typeA1Params.toString());
		// 从文件a1_3_128.properties中读取参数初始化双线性群
		typeA1Params = PairingFactory.getPairingParameters(PairingUtils.PATH_a1_3_128);
		// 初始化Pairing
		Pairing pairing = PairingFactory.getPairing(typeA1Params);
		// The number of algebraic structures available
		logger.info("degree: " + pairing.getDegree());
		BigInteger p = typeA1Params.getBigInteger("p");
		logger.info("p bit length: " + p.toString(2).length());
		BigInteger l = typeA1Params.getBigInteger("l");
		BigInteger n = typeA1Params.getBigInteger("n");
		logger.info("n bit length: " + n.toString(2).length());
		BigInteger n0 = typeA1Params.getBigInteger("n0");
		logger.info("n0 bit length: " + n0.toString(2).length());
		BigInteger n1 = typeA1Params.getBigInteger("n1");
		BigInteger n2 = typeA1Params.getBigInteger("n2");
		assertEquals(n, n0.multiply(n1).multiply(n2));
		assertTrue(p.add(new BigInteger("1")).equals(n.multiply(l)));
	}

	/**
	 * test dynamically generate and save Type F PairingParameters
	 * <p>
	 * asymmetric prime-order bilinear pairing
	 */
	@Ignore
	@Test
	public void testGenTypeFPairParam() {
		int rbits = 512; // rbits是Z其中阶数p的比特长度 a,b属于Zr={0,...,p-1}
		// 通过代码动态生成Pairing对象
		PairingParameters typeFParams = PairingUtils.genTypeFPairParam(rbits);
		// 将参数写入文件f_512.properties中，使用Princeton大学封装的文件输出库
		Out out = new Out(PairingUtils.PATH_f_512);
		out.println(typeFParams);
		// print Pairing parameters
		logger.info(typeFParams.toString());
		// 从文件f_512.properties中读取参数初始化双线性群
		typeFParams = PairingFactory.getPairingParameters(PairingUtils.PATH_f_512);
		// 初始化Pairing
		Pairing pairing = PairingFactory.getPairing(typeFParams);
		// The number of algebraic structures available
		logger.info("degree: j" + pairing.getDegree());
		BigInteger q = new BigInteger(typeFParams.getString("q"));
		logger.info("q bit length: " + q.toString(2).length());
		BigInteger r = typeFParams.getBigInteger("r");
		logger.info("r bit length: " + r.toString(2).length());
		BigInteger b = typeFParams.getBigInteger("b");
		logger.info("b bit length: " + b.toString(2).length());
	}

	/**
	 *   验证hash函数H是否具有同态性质: H(a)*H(b)=H(a*b)
	 * H(a) = (x1,y1); H(b)=(x2,y2)
	 * x = x1*x2-y1*y2
	 * y = (x1+y1)*(x2+y2)-x1*x2-y1*y2
	 */

	@Ignore
	@Test
	@SuppressWarnings({ "unchecked", "unused" })
	public void testHomomorphismOfHash_H() {
		PairingParameters typeAParams = PairingFactory
				.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		Pairing pairing = PairingFactory.getPairing(typeAParams);
		ZrField Zr = (ZrField) pairing.getZr();
		CurveField<ZrField> G1 = (CurveField<ZrField>) pairing.getG1();
		GTFiniteField<DegreeTwoExtensionQuadraticField<ZrField>> GT = (GTFiniteField<DegreeTwoExtensionQuadraticField<ZrField>>) pairing
				.getGT();
		Element a = GT.newRandomElement().getImmutable();
		Element b = GT.newRandomElement().getImmutable();
		Element Ha = PairingUtils.hash_H(pairing, a);
		Element Hb = PairingUtils.hash_H(pairing, b);
		Element Hab = PairingUtils.hash_H(pairing, a.mul(b));
		boolean isEqual = Hab.isEqual(Ha.add(Hb));
		assertTrue(isEqual);
		if (isEqual) {
			logger.info("the function H have the nature of homomorphism");
		}
	}

	// 验证 [H(g^r1) + H(g^r2)] = [H(g^(r1+r2))]
	// 因为 H具有同态性质: H(g^r1) * H(g^r2) = H(g^r1*g^r2);且g^r1*g^r2 = g^(r1+r2);所以成立
	@Ignore
	@Test
	@SuppressWarnings("unchecked")
	public void testHomomorphismOfHash_H2() {

		PairingParameters typeAParams = PairingFactory
				.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		Pairing pairing = PairingFactory.getPairing(typeAParams);
		ZrField Zr = (ZrField) pairing.getZr();
		CurveField<ZrField> G1 = (CurveField<ZrField>) pairing.getG1();

		Element P = G1.newRandomElement().getImmutable();// 生成G1的生成元P
		Element s = Zr.newRandomElement().getImmutable();// //随机生成主密钥s
		Element Ppub = P.mulZn(s).getImmutable();// 计算Ppub=sP,注意顺序
		Element Qu = PairingUtils.hash_G(pairing, "IDu");

		Element r1 = Zr.newRandomElement().getImmutable();
		Element r2 = Zr.newRandomElement().getImmutable();
		Element g = pairing.pairing(Qu, Ppub).getImmutable();

		Element gr1 = g.powZn(r1).getImmutable();
		Element H1 = PairingUtils.hash_H(pairing, gr1);

		Element gr2 = g.powZn(r2).getImmutable();

		Element H2 = PairingUtils.hash_H(pairing, gr2);

		Element gr12 = g.powZn(r1.add(r2)).getImmutable();
		Element H12 = PairingUtils.hash_H(pairing, gr12);

		logger.info("gr1    :" + gr1);
		logger.info("gr2    :" + gr2);
		logger.info("gr12   :" + gr12);
		logger.info("gr1+gr2:" + gr1.add(gr2));
		assertTrue(gr12.equals(gr1.add(gr2)));

		logger.info("H1   :" + H1);
		logger.info("H2   :" + H2);
		logger.info("H12  :" + H12);
		logger.info("H1+H2:" + H1.add(H2));

		boolean isEqual = H12.toBigInteger().equals(H1.add(H2).toBigInteger());
		assertTrue(isEqual);

		if (isEqual) {
			logger.info("[H(g^r1) + H(g^r2)].toBigInteger = [H(g^(r1+r2))].toBigInteger does hold");
		}
	}

	/**
	 *   验证 V1+V2 ?= (M1+M2) add (H1+H2)
	 * GTElement中元素无论加法add还是乘法mul，都是通过DegreeTwoExtensionQuadraticElement中的mul计算的
	 * x = x1*x2-y1*y2
	 * y = (x1+y1)*(x2+y2)-x1*x2-y1*y2
	 */
//	@Ignore
	@Test
	public void test_xor() {
		PairingParameters typeAParams = PairingFactory
				.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		TypeAPairing pairing = (TypeAPairing) PairingFactory.getPairing(typeAParams);
		String message1 = "12";
		String message2 = "11";
		Element M1 = PairingUtils.mapNumStringToElement(pairing, message1, PairingGroupType.GT);
		Element M2 = PairingUtils.mapNumStringToElement(pairing, message2, PairingGroupType.GT);

		Element P = pairing.getG1().newRandomElement().getImmutable();// 生成G1的生成元P
		Element s = pairing.getZr().newRandomElement().getImmutable();// //随机生成主密钥s
		Element Ppub = P.mulZn(s).getImmutable();// 计算Ppub=sP,注意顺序
		Element Qu = PairingUtils.hash_G(pairing, "IDu");
		Element g = pairing.pairing(Qu, Ppub).getImmutable();

		Element r1 = pairing.getZr().newRandomElement().getImmutable();
		Element gr1 = g.powZn(r1).getImmutable();
		Element H1 = PairingUtils.hash_H(pairing, gr1);

		Element r2 = pairing.getZr().newRandomElement().getImmutable();
		Element gr2 = g.powZn(r2).getImmutable();
		Element H2 = PairingUtils.hash_H(pairing, gr2);

		Element gr12 = g.powZn(r1.add(r2)).getImmutable();
		Element gr12_temp = gr1.mul(gr2).getImmutable();
		// 测试g^r1 * g^r2 = g^(r1+r2)
		assertTrue(gr12.isEqual(gr12_temp));

		Element H12 = PairingUtils.hash_H(pairing, gr12);
		// 测试函数hash_H的同态性质 hash_H(g^r1)+hash_H(g^r2)=hash_H(g^r1*g^r2)=hash_H(g^(r1+r2))
		assertTrue(H12.isEqual(H1.add(H2)));

		// 方案一: 以BigInteger作为基本数据类型 String<->BigInteger ; Element<->BigInteger
		// 测试Element 与BigInteger之间的可逆性

		// BigInteger转Element数据完整，成功!!!
		BigInteger bi = new BigInteger("12345678900987654323456789");
		Element e = pairing.getGT().newElement(bi).getImmutable();
		assertTrue(bi.equals(e.toBigInteger()));

		// Element转BigInteger会有数据丢失，所以失败！！！
		BigInteger biH12 = H12.toBigInteger();
		Element Temp_H12 = pairing.getGT().newElement(biH12).getImmutable();
		assertFalse(H12.equals(Temp_H12));

		// 方案二: 以bytes作为基本数据类型 String<->BigInteger<->bytes ; Element<->bytes
		// 测试String和BigInteger的可逆性(成功!)
		String message = "1235678901234567890";
		String Temp_message = new BigInteger(message).toString();
		assertTrue(message.equals(Temp_message));

		// 测试BigInteger和bytes的可逆性(成功!)
		BigInteger biMessage = new BigInteger(message);
		BigInteger temp_biMessage = new BigInteger(biMessage.toByteArray());
		assertTrue(biMessage.equals(temp_biMessage));

		// 测试Element和bytes的可逆性(成功!)
		Temp_H12 = pairing.getGT().newElementFromBytes(H12.toBytes()).getImmutable();
		assertTrue(H12.isEqual(Temp_H12));

		// 测试Element 与BigInteger之间通过bytes的可逆性(成功!)
		byte[] bytes1 = biMessage.toByteArray();
		Element Temp = pairing.getGT().newElementFromBytes(bytes1).getImmutable();
		byte[] bytes2 = Temp.toBytes();
		int byteLen = Temp.getLengthInBytes();
		temp_biMessage = new BigInteger(Arrays.copyOf(bytes2, byteLen / 2));
		assertTrue(biMessage.equals(temp_biMessage));

		// V1 = M1 mul H1
		BigInteger biMessage1 = new BigInteger(message1);
//		H1 = pairing.getGT().newElement(new BigInteger("3")).getImmutable();
		logger.info("M1   :" + biMessage1);
		logger.info("H1   :" + H1);
		Element V1 = M1.mul(H1);
		logger.info("V1   :" + V1);

		// V2 = M2 mul H2
		BigInteger biMessage2 = new BigInteger(message2);
//		H2 = pairing.getGT().newElement(new BigInteger("4")).getImmutable();
		logger.info("M2   :" + biMessage2);
		logger.info("H2   :" + H2);
		Element V2 = M2.mul(H2);
		logger.info("V2   :" + V2);

		// V12=V1 + V2
		Element V12 = V1.add(V2);
		logger.info("V1+V2:" + V12);

		// M12 = M1+M2
		Element M12 = M1.add(M2);
		// H12 = H1 + H2
		H12 = H1.add(H2);

		// V1_2 = (M1+M2) mul (H1+H2)
		Element V1_2 = M12.mul(H12);
		logger.info("V1_2 :" + V1_2);
		assertTrue(V12.isEqual(V1_2));
	}
}
