package com.example.encryption.ibe;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;

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
import cn.edu.ncepu.crypto.encryption.ibe.wp_ibe.BasicIBE.CipherText;
import cn.edu.ncepu.crypto.encryption.ibe.wp_ibe.IBE;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import cn.edu.ncepu.crypto.utils.TimeCountProxyHandle;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * IBE engine test.
 */
public class IBEEngineJUnitTest {
	private static Logger logger = LoggerFactory.getLogger(IBEEngineJUnitTest.class);
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
		Element message = PairingUtils.mapNumStringToElement(pairing, plainMessage, PairingGroupType.GT);
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

			// test invalid example
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
	 * TODO 本质是testIBEBF01bEngine,不同之出是加载的参数是a.properties
	 */
	@Ignore
	@Test
	public void testBasicIBE() {
		logger.info("start BasicIBE Testing \n");
		String message = "123456789012345678901234567890123456789012345678901234567890";
		// 在jpbc配置使用的那个jar包，\params\curves下面
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		BasicIBE ident = new BasicIBE(pairingParams);
		// 动态代理，统计各个方法耗时
		IBE identProxy = (IBE) Proxy.newProxyInstance(BasicIBE.class.getClassLoader(), new Class[] { IBE.class },
				new TimeCountProxyHandle(ident));
		logger.info("--------------------系统建立阶段----------------------");
		identProxy.setup();
		logger.info("--------------------密钥提取阶段----------------------");
		Element d = identProxy.extract("uID");
		logger.info("----------------------加密阶段-----------------------");
		logger.info("plaintext: " + message);
		CipherText cipherText = identProxy.encrypt(message);
		logger.info("-----------------------解密阶段----------------------");
		String decrypted = identProxy.decrypt(d, cipherText);
		logger.info("decrypted: " + decrypted);
		assertTrue(message.equals(decrypted));
	}

	/**
	 * TODO GTElement的add方法跟mul方法的实现方式一模一样，满足乘法同态而不是加法同态
	 * C1 = IBEHE(M1) C2 = IBEHE(M2)  IBEHE(M1*M2) = C1+C2
	 */
//	@Ignore
	@Test
	public void testHomomorphismOfBasicIBE() {
		// 在jpbc配置使用的那个jar包，\params\curves下面
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		Pairing pairing = PairingFactory.getPairing(pairingParams);
		BasicIBE basicIBE = new BasicIBE(pairingParams);
		String topLayerAdmin = "TopLayerAdmin";
		Map<String, CipherText> ciphertextMap = new LinkedHashMap<String, CipherText>();
		logger.info("--------------------系统建立阶段----------------------");
		basicIBE.setup();
		logger.info("--------------------密钥提取阶段----------------------");
		Element d = basicIBE.extract(topLayerAdmin);
		logger.info("----------------------加密阶段-----------------------");

		String num_user1_org1 = "2323232342342323423234234";
		Element e_num_user1_org1 = PairingUtils.mapNumStringToElement(pairing, num_user1_org1, PairingGroupType.GT);
		CipherText ciphertext_user1_org1 = basicIBE.encrypt(num_user1_org1);
		ciphertextMap.put("user1_org1", ciphertext_user1_org1);
		String num_user2_org1 = "2342342342342342344";
		Element e_num_user2_org1 = PairingUtils.mapNumStringToElement(pairing, num_user2_org1, PairingGroupType.GT);
		CipherText ciphertext_user2_org1 = basicIBE.encrypt(num_user2_org1);
		ciphertextMap.put("user2_org1", ciphertext_user2_org1);

		logger.info("--------------------数据聚合阶段----------------------");
		CipherText ciphertext_org1 = basicIBE.add(ciphertextMap);
		logger.info("--------------------密文验证阶段----------------------");
		// 验证U
		Element U1 = ciphertext_user1_org1.getU();
		Element U2 = ciphertext_user2_org1.getU();
		Element U12 = ciphertext_org1.getU();
		assertTrue(U12.isEqual(U1.add(U2)));
		// 验证V
		Element V1 = ciphertext_user1_org1.getV();
		Element V2 = ciphertext_user2_org1.getV();
		Element V12 = ciphertext_org1.getV();
		assertTrue(V12.equals(V1.add(V2)));
		// 验证r
		Element r1 = ciphertext_user1_org1.getR();
		Element r2 = ciphertext_user2_org1.getR();
		Element r12 = ciphertext_org1.getR();
		assertTrue(r12.isEqual(r1.add(r2)));
		// 验证g
		Element g1 = ciphertext_user1_org1.getG();
		Element g2 = ciphertext_user2_org1.getG();
		Element g12 = ciphertext_org1.getG();
		assertTrue((g1.isEqual(g2) && g2.isEqual(g12)));
		// 验证gr
		Element gr1 = ciphertext_user1_org1.getGr();
		Element gr2 = ciphertext_user2_org1.getGr();
		Element gr12 = ciphertext_org1.getGr();
		assertTrue(gr12.isEqual(gr1.mul(gr2)) && gr12.isEqual(g12.powZn(r12)));
		// 验证H
		Element H1 = ciphertext_user1_org1.getH();
		Element H2 = ciphertext_user2_org1.getH();
		Element H12 = ciphertext_org1.getH();
		assertTrue(H12.isEqual(H1.add(H2)));
		logger.info("-----------------------解密阶段----------------------");
		String decrypted = basicIBE.decrypt(d, ciphertext_org1);
		logger.info("decrypted: " + decrypted);
		Element e_decrypted = PairingUtils.mapNumStringToElement(pairing, decrypted, PairingGroupType.GT);
		Element preNum = e_num_user1_org1.mul(e_num_user2_org1);
		assertTrue(preNum.isEqual(e_decrypted));

		// --------------------------------------------------------

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
