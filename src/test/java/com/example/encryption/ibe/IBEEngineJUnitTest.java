package com.example.encryption.ibe;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.IBEEngine;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.IBEBF01aEngine;
import cn.edu.ncepu.crypto.encryption.ibe.bf01b.IBEBF01bEngine;
import cn.edu.ncepu.crypto.encryption.ibe.gen06a.IBEGen06aEngine;
import cn.edu.ncepu.crypto.encryption.ibe.gen06b.IBEGen06bEngine;
import cn.edu.ncepu.crypto.encryption.ibe.lw10.IBELW10Engine;
import cn.edu.ncepu.crypto.encryption.ibe.wp_ibe.BasicIBE;
import cn.edu.ncepu.crypto.encryption.ibe.wp_ibe.IBE;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import cn.edu.ncepu.crypto.utils.SysProperty;
import cn.edu.ncepu.crypto.utils.TimeCountProxyHandle;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * IBE engine test.
 */
public class IBEEngineJUnitTest {
	private static Logger logger = LoggerFactory.getLogger(IBEEngineJUnitTest.class);
	private static String USER_DIR = SysProperty.USER_DIR;
	private static final String identity_1 = "ID_1";
	private static final String identity_2 = "ID_2";
	private PairingParameters pairingParams = null;

	private IBEEngine engine;

	private void try_valid_enc_dec(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext) {
		try {
			try_enc_dec(pairing, publicKey, masterKey, identityForSecretKey, identityForCiphertext);
		} catch (Exception e) {
			logger.info("Valid decryption test failed, " + "secret key identity  = " + identityForSecretKey + ", "
					+ "ciphertext identity = " + identityForCiphertext);
			logger.info(e.getLocalizedMessage());
			System.exit(1);
		}
	}

	private void try_invalid_enc_dec(Pairing pairing, PairingKeySerParameter publicKey,
			PairingKeySerParameter masterKey, String identityForSecretKey, String identityForCiphertext) {
		try {
			try_enc_dec(pairing, publicKey, masterKey, identityForSecretKey, identityForCiphertext);
		} catch (InvalidCipherTextException e) {
			logger.info(e.getLocalizedMessage());
			logger.info("Invalid decryption test passed!, " + "secret key identity  = " + identityForSecretKey + ", "
					+ "ciphertext identity = " + identityForCiphertext);
		} catch (ClassNotFoundException e) {
			logger.info(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.info(e.getLocalizedMessage());
		}
	}

	private void try_enc_dec(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext)
			throws InvalidCipherTextException, IOException, ClassNotFoundException {
		// KeyGen and serialization
		PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityForSecretKey);
		byte[] byteArraySecretKey = PairingUtils.SerCipherParameter(secretKey);
		CipherParameters anSecretKey = PairingUtils.deserCipherParameters(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// Encryption and serialization
		// the message waits to be encrypted
		String plainMessage = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
		logger.info("plaintext message: " + plainMessage);
		Element message = PairingUtils.mapNumStringToElement(pairingParams, pairing, plainMessage, PairingGroupType.GT);
		PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityForCiphertext, message);
		byte[] byteArrayCiphertext = PairingUtils.SerCipherParameter(ciphertext);
		CipherParameters anCiphertext = PairingUtils.deserCipherParameters(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		Element anMessage = engine.decryption(publicKey, secretKey, identityForCiphertext, ciphertext);
		String decMessage = PairingUtils.mapElementToNumString(anMessage);
		logger.info("decrypted message: " + decMessage);
		// new String(anMessage.toBigInteger().toByteArray(), "UTF-8"));
		Assert.assertEquals(plainMessage, decMessage);

		// Encapsulation and serialization
		// 将Qu(identityForCiphertext)和Ppub(publicKey)封装成(U,session key)
		// U=rP: PairingCipherSerParameter header
		// session key=e(Qu,Ppub)^r=e(Qu,sP)^r=e(Qu,P)^rs: byte[] sessionKey
		PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityForCiphertext);
		byte[] sessionKey = encapsulationPair.getSessionKey();
		PairingCipherSerParameter header = encapsulationPair.getHeader();
		byte[] byteArrayHeader = PairingUtils.SerCipherParameter(header);
		CipherParameters anHeader = PairingUtils.deserCipherParameters(byteArrayHeader);
		Assert.assertEquals(header, anHeader);
		header = (PairingCipherSerParameter) anHeader;

		// Decapsulation
		// 将d(secretKey)和U(header)解封装得到session key
		// session key=e(d,U)=e(sQu, rP)=e(Qu,P)^rs
		// U在发送方(identityForCiphertext)序列化后通过Internet传输过来
		byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityForCiphertext, header);
		Assert.assertArrayEquals(sessionKey, anSessionKey);
	}

	private void runAllTests(PairingParameters pairingParameters) {
		// 初始化Pairing
		Pairing pairing = PairingFactory.getPairing(pairingParameters);
		try {
			// Setup and serialization
			PairingKeySerPair keyPair = engine.setup(pairingParameters);
			// get publicKey include (P, Ppub), where Ppub=sP
			PairingKeySerParameter publicKey = keyPair.getPublic();
			byte[] byteArrayPublicKey = PairingUtils.SerCipherParameter(publicKey);
			CipherParameters anPublicKey = PairingUtils.deserCipherParameters(byteArrayPublicKey);
			Assert.assertEquals(publicKey, anPublicKey);
			publicKey = (PairingKeySerParameter) anPublicKey;

			// get master-key s
			PairingKeySerParameter masterKey = keyPair.getPrivate();
			byte[] byteArrayMasterKey = PairingUtils.SerCipherParameter(masterKey);
			CipherParameters anMasterKey = PairingUtils.deserCipherParameters(byteArrayMasterKey);
			Assert.assertEquals(masterKey, anMasterKey);
			masterKey = (PairingKeySerParameter) anMasterKey;

			// test valid example
			logger.info("Test valid examples");
			try_valid_enc_dec(pairing, publicKey, masterKey, identity_1, identity_1);
			try_valid_enc_dec(pairing, publicKey, masterKey, identity_2, identity_2);
			logger.info("");

			// test valid example
			logger.info("Test invalid examples");
			try_invalid_enc_dec(pairing, publicKey, masterKey, identity_1, identity_2);
			try_invalid_enc_dec(pairing, publicKey, masterKey, identity_2, identity_1);
			logger.info(engine.getEngineName() + " test passed!");
		} catch (ClassNotFoundException e) {
			logger.info("setup test failed.");
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			logger.info("setup test failed.");
			e.printStackTrace();
			System.exit(1);
		}
	}

	/**
	 * TODO 测试动态生成Type A PairingParameters并保存
	 */
	@Ignore
	@Test
	public void testGenTypeAPairParam() {
		this.engine = IBEBF01aEngine.getInstance();
		int rbits = 80; // rbits是Z其中阶数p的比特长度 a,b属于Zr={0,...,p-1}
		int qbits = 1024; // qBit是域Fq的中q的比特长度，G是由定义在域Fq上的椭圆曲线E上的点(x,y的取值范围是Fq)构成的群，
							// G的阶数(即G的元素个数)的比特长度为r。q,r存在一定的关系，比如r=(q+1)/6
		// 通过代码动态生成Pairing对象
		// 指定椭圆曲线的种类
		TypeACurveGenerator pairParamGenerator = new TypeACurveGenerator(rbits, qbits);
		// 产生椭圆曲线参数
		PairingParameters typeAParams = pairParamGenerator.generate();
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
		logger.info("" + pairing.getDegree());

		BigInteger q = new BigInteger(typeAParams.getString("q"));
		logger.info("q bit length: " + q.toString(2).length());
		logger.info("");
	}

	/**
	 * TODO 测试动态生成Type A1 PairingParameters并保存
	 */
	@Ignore
	@Test
	public void testGenTypeA1PairParam() {
		// Type A1 对称合数阶双线性群
		this.engine = IBELW10Engine.getInstance();
		int numPrime = 3; // numPrime是阶数N中有几个质数因子
		int qBit = 128; // qBit是每个质数因子的比特长度

		// Type A1涉及到的阶数很大，其参数产生的时间也比较长
		// 指定椭圆曲线的种类
		TypeA1CurveGenerator pairParamGenerator = new TypeA1CurveGenerator(numPrime, qBit);
		// 产生椭圆曲线参数
		PairingParameters typeA1Params = pairParamGenerator.generate();
		// 将参数写入文件a_80_256.properties中，使用Princeton大学封装的文件输出库
		Out out = new Out(USER_DIR + "/elements/a1_3_128.properties");
		out.println(typeA1Params);
		// print Pairing parameters
		logger.info(typeA1Params.toString());
		// 从文件a1_3_128.properties中读取参数初始化双线性群
		typeA1Params = PairingFactory.getPairingParameters("/elements/a1_3_128.properties");
		// 初始化Pairing
		Pairing pairing = PairingFactory.getPairing(typeA1Params);
		// The number of algebraic structures available
		logger.info("" + pairing.getDegree());
	}

	/**
	 * TODO 本质是testIBEBF01bEngine,不同之出是加载的参数是a.properties
	 */
//	@Ignore
	@Test
	public void testBasicIBE() {
		logger.info("start wp_ibe Testing \n");
		// 在jpbc配置使用的那个jar包，\params\curves下面
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		BasicIBE ident = new BasicIBE(pairingParams);
		// 动态代理，统计各个方法耗时
		IBE identProxy = (IBE) Proxy.newProxyInstance(BasicIBE.class.getClassLoader(), new Class[] { IBE.class },
				new TimeCountProxyHandle(ident));
		identProxy.setup();
		identProxy.extract();
		identProxy.encrypt();
		identProxy.decrypt();
	}

	@Ignore
	@Test
	public void testIBEBF01aEngine() {
		this.engine = IBEBF01aEngine.getInstance();
		// Type A 对称质数阶双线性群
		// 通过文件读取初始化Pairing对象
		// 从文件中读取PairingParameters对象
		// PairingParameters的toString()可以用来将Pairing参数存放在文件中
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		runAllTests(pairingParams);
	}

	@Ignore
	@Test
	public void testIBEBF01bEngine() {
		this.engine = IBEBF01bEngine.getInstance();
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		runAllTests(pairingParams);
	}

	@Ignore
	@Test
	public void testIBEGen06aEngine() {
		this.engine = IBEGen06aEngine.getInstance();
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		runAllTests(pairingParams);
	}

	@Ignore
	@Test
	public void testIBEGen06bEngine() {
		this.engine = IBEGen06bEngine.getInstance();
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		runAllTests(pairingParams);
	}

	@Ignore
	@Test
	public void testIBELW10Engine() {
		this.engine = IBELW10Engine.getInstance();
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128);
		runAllTests(pairingParams);
	}
}
