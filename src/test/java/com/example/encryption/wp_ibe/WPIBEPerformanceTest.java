/**
 * 
 */
package com.example.encryption.wp_ibe;

import java.lang.reflect.Proxy;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import cn.edu.ncepu.crypto.encryption.wp_ibe.BasicIdent2;
import cn.edu.ncepu.crypto.encryption.wp_ibe.Ident;
import cn.edu.ncepu.crypto.utils.TimeCountProxyHandle;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 *
 * @版权 : Copyright (c) 2018-2019 E1101智能电网信息安全中心
 * @author: Hu Baiji
 * @E-mail: drbjhu@163.com
 * @创建日期: 2019年10月16日 下午8:30:24
 * @ClassName WPIBETest
 * @class Description:  动态代理，统计各个方法耗时 Generic IBE performance test.
 * @修改记录:
 * @版本: 1.0
 */
public class WPIBEPerformanceTest {

	private static final String default_path = "params/a.properties";
	private Pairing pairing = PairingFactory.getPairing(default_path);// 在jpbc配置使用的那个jar包，\params\curves下面

	@Before
	public void setUp() throws Exception {
		System.out.printf("@Before \n");
	}

	@After
	public void tearDown() throws Exception {
		System.out.printf("@After \n");
	}

	@Test
	public void testCompareStrings() throws Exception {
		System.out.printf("start unit Testing \n");
		BasicIdent2 ident = new BasicIdent2(pairing);
		// 动态代理，统计各个方法耗时
		Ident identProxy = (Ident) Proxy.newProxyInstance(BasicIdent2.class.getClassLoader(),
				new Class[] { Ident.class }, new TimeCountProxyHandle(ident));
		identProxy.buildSystem();
		identProxy.extractSecretKey();
		identProxy.encrypt();
		identProxy.decrypt();
	}
}
