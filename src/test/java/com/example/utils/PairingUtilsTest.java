/**
 * 
 */
package com.example.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jul 5, 2020 3:13:04 PM
 * @ClassName PairingUtilsTest
 * @Description: TODO(test methods of PairingUtils)
 */
public class PairingUtilsTest {
	private static Logger logger = LoggerFactory.getLogger(PairingUtilsTest.class);
	private static String USER_DIR = SysProperty.USER_DIR;

	/**
	 * TODO 测试动态生成Type A PairingParameters并保存
	 */
	@Ignore
	@Test
	public void testGenTypeAPairParam() {
		int rbits = 80; // rbits是Z其中阶数p的比特长度 a,b属于Zr={0,...,p-1}
		int qbits = 1024; // qBit是域Fq的中q的比特长度，G是由定义在域Fq上的椭圆曲线E上的点(x,y的取值范围是Fq)构成的群，
							// G的阶数(即G的元素个数)的比特长度为r。q,r存在一定的关系，比如r=(q+1)/6
		// 通过代码动态生成Pairing对象
		PairingParameters typeAParams = PairingUtils.genTypeAPairParam(rbits, qbits);
		// 将参数写入文件a_80_256.properties中，使用Princeton大学封装的文件输出库
		Out out = new Out(USER_DIR + "/elements/a_80_1024.properties");
		out.println(typeAParams);
		// print Pairing parameters
		logger.info(typeAParams.toString());
		// 从文件a_80_256.properties中读取参数初始化双线性群
		typeAParams = PairingFactory.getPairingParameters(USER_DIR + "/elements/a_80_1024.properties");
		// 初始化Pairing
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
	 * TODO 测试动态生成Type A1 PairingParameters并保存
	 */
//	@Ignore
	@Test
	public void testGenTypeA1PairParam() {
		// Type A1 对称合数阶双线性群
		int numPrime = 3; // numPrime是阶数N中有几个质数因子
		int bits = 128; // bit是每个质数因子的比特长度

		// Type A1涉及到的阶数很大，其参数产生的时间也比较长
		PairingParameters typeA1Params = PairingUtils.genTypeA1PairParam(numPrime, bits);
		// 将参数写入文件a_80_256.properties中，使用Princeton大学封装的文件输出库
		Out out = new Out(USER_DIR + "/elements/a1_3_128.properties");
		out.println(typeA1Params);
		// print Pairing parameters
		logger.info(typeA1Params.toString());
		// 从文件a1_3_128.properties中读取参数初始化双线性群
		typeA1Params = PairingFactory.getPairingParameters(USER_DIR + "/elements/a1_3_128.properties");
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
}
