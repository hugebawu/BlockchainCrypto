/**
 * 
 */
package com.example.homomorphicencryption.ibeHE;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
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
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.homomorphicEncryption.CipherText;
import cn.edu.ncepu.crypto.homomorphicEncryption.HE;
import cn.edu.ncepu.crypto.homomorphicEncryption.basicIBEHE.BasicIBEHEEngine;
import cn.edu.ncepu.crypto.homomorphicEncryption.basicIBEHE.IBEHECipherText;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.IBEHEEngine;
import cn.edu.ncepu.crypto.homomorphicEncryption.ibeHE.bf01aHE.BF01aHEEngine;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import cn.edu.ncepu.crypto.utils.TimeCountProxyHandle;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 8, 2020 11:47:24 AM
 * @ClassName IBEHEEngineTest
 * @Description: TODO(IBE-based homomorphic encryption engine test.)
 */
public class IBEHEEngineTest {
	private static Logger logger = LoggerFactory.getLogger(IBEHEEngineTest.class);
	private static final String identity_1 = "ID_1";
	private static final String identity_2 = "ID_2";
	private PairingParameters pairingParams = null;

	private IBEHEEngine engine;

	private void try_valid_enc_dec(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
			String identityForSecretKey, String identityForCiphertext) {
		try {
			try_enc_dec(pairing, publicKey, masterKey, identityForSecretKey, identityForCiphertext);
		} catch (Exception e) {
			logger.info("Valid decryption test failed, " + "secret key identity  = " + identityForSecretKey + ", "
					+ "ciphertext identity = " + identityForCiphertext);
			logger.info(e.getLocalizedMessage());
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
		PairingKeySerParameter secretKey = engine.extract(identityForSecretKey, masterKey);
		byte[] byteArraySecretKey = PairingUtils.SerCipherParameter(secretKey);
		CipherParameters anSecretKey = PairingUtils.deserCipherParameters(byteArraySecretKey);
		Assert.assertEquals(secretKey, anSecretKey);
		secretKey = (PairingKeySerParameter) anSecretKey;

		// Encryption and serialization
		// the message waits to be encrypted
		String plainMessage = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
		logger.info("plaintext message: " + plainMessage);
		Element message = PairingUtils.mapNumStringToElement(pairing, plainMessage, PairingGroupType.GT);
		PairingCipherSerParameter ciphertext = engine.encrypt(publicKey, identityForCiphertext, message);
		byte[] byteArrayCiphertext = PairingUtils.SerCipherParameter(ciphertext);
		CipherParameters anCiphertext = PairingUtils.deserCipherParameters(byteArrayCiphertext);
		Assert.assertEquals(ciphertext, anCiphertext);
		ciphertext = (PairingCipherSerParameter) anCiphertext;

		// Decryption
		Element anMessage = engine.decrypt(secretKey, identityForCiphertext, ciphertext);
		String decMessage = PairingUtils.mapElementToNumString(anMessage, PairingGroupType.GT);
		logger.info("decrypted message: " + decMessage);
		// new String(anMessage.toBigInteger().toByteArray(), "UTF-8"));
		Assert.assertEquals(plainMessage, decMessage);
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
			logger.info("");
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
	 * TODO 测试BF01aHE的加密解密功能
	 */
	@Ignore
	@Test
	public void testBF01aHEEngine() {
		this.engine = BF01aHEEngine.getInstance();
		// Type A 对称质数阶双线性群
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		runAllTests(pairingParams);
	}

	/**
	 * TODO 测试BasicIBE(本质是IBEBF01aEngine的非抽象实现方式)的加密解密功能
	 */
	@Ignore
	@Test
	public void testBasicIBE() {
		logger.info("start BasicIBE Testing \n");
		String message = "123456789012345678901234567890123456789012345678901234567890";
		// 在jpbc配置使用的那个jar包，\params\curves下面
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		BasicIBEHEEngine ident = new BasicIBEHEEngine(pairingParams);
		// 动态代理，统计各个方法耗时
		HE identProxy = (HE) Proxy.newProxyInstance(BasicIBEHEEngine.class.getClassLoader(), new Class[] { HE.class },
				new TimeCountProxyHandle(ident));
		logger.info("--------------------系统建立阶段----------------------");
		identProxy.setup();
		logger.info("--------------------密钥提取阶段----------------------");
		Element d = identProxy.keyGen("uID");
		logger.info("----------------------加密阶段-----------------------");
		logger.info("plaintext: " + message);
		CipherText cipherText = identProxy.encrypt(message);
		logger.info("-----------------------解密阶段----------------------");
		String decrypted = identProxy.decrypt(d, cipherText);
		logger.info("decrypted: " + decrypted);
		try {
			assertTrue(message.equals(decrypted));
			logger.info("BasicIBE encryption and decryption test passed!");
		} catch (Exception e) {
			logger.info("BasicIBE encryption and decryption test failed!");
			logger.info("" + e.getLocalizedMessage());
		}
	}

	/**
	 * TODO GTElement的add方法跟mul方法的实现方式一模一样，满足乘法同态而不是加法同态
	 * C1 = BasicIBEHE(M1) C2 = BasicIBEHE(M2)  C1+C2 = BasicIBEHE(M1*M2)
	 */
	@Ignore
	@Test
	public void testHomomorphismOfBasicIBE() {
		// 在jpbc配置使用的那个jar包，\params\curves下面
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		Pairing pairing = PairingFactory.getPairing(pairingParams);
		BasicIBEHEEngine basicIBE = new BasicIBEHEEngine(pairingParams);
		String topLayerAdmin = "TopLayerAdmin";
		Map<String, CipherText> ciphertextMap = new LinkedHashMap<String, CipherText>();
		logger.info("--------------------系统建立阶段----------------------");
		basicIBE.setup();
		logger.info("--------------------密钥提取阶段----------------------");
		Element d = basicIBE.keyGen(topLayerAdmin);
		logger.info("----------------------加密阶段-----------------------");
		String num_user1_org1 = "12";
		Element e_num_user1_org1 = PairingUtils.mapNumStringToElement(pairing, num_user1_org1, PairingGroupType.GT);
		IBEHECipherText ciphertext_user1_org1 = basicIBE.encrypt(num_user1_org1);
		ciphertextMap.put("user1_org1", ciphertext_user1_org1);
		String num_user2_org1 = "12";
		Element e_num_user2_org1 = PairingUtils.mapNumStringToElement(pairing, num_user2_org1, PairingGroupType.GT);
		IBEHECipherText ciphertext_user2_org1 = basicIBE.encrypt(num_user2_org1);
		ciphertextMap.put("user2_org1", ciphertext_user2_org1);
		logger.info("--------------------数据聚合阶段----------------------");
		IBEHECipherText ciphertext_org1 = (IBEHECipherText) basicIBE.eval(ciphertextMap);
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
		try {
			assertTrue(preNum.isEqual(e_decrypted));
			logger.info("BasicIBE possesses multiplicative homomorphism!");
		} catch (Exception e) {
			logger.info("BasicIBE homomorphism test failed!");
			logger.info("" + e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	// 经验证只有乘法同态性质
	public void testHomomorphismOfBF01aHE() {
		this.engine = BF01aHEEngine.getInstance();
		// Type A 对称质数阶双线性群
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		// 初始化Pairing
		Pairing pairing = PairingFactory.getPairing(pairingParams);
		PairingKeySerPair keyPair = engine.setup(pairingParams);
		// get system publicKey include (P, Ppub), where Ppub=sP
		PairingKeySerParameter publicKey = keyPair.getPublic();
		// get system masterkey s
		PairingKeySerParameter masterKey = keyPair.getPrivate();

		String topLayerAdmin = "TopLayerAdmin";
		// topLayerAdmin secret key extract
		PairingKeySerParameter secretKey = engine.extract(topLayerAdmin, masterKey);

		try {
			Map<String, PairingCipherSerParameter> ciphertextMap = new LinkedHashMap<String, PairingCipherSerParameter>();

			// user1_org1 collect, encrypt and report data
			String num_user1_org1 = "11";
			BigInteger q = pairingParams.getBigInteger("q");
			Element e_num_user1_org1 = PairingUtils.mapNumStringToElement(pairing, num_user1_org1, PairingGroupType.GT);
			logger.info("e_num_user1_org1:" + e_num_user1_org1);
			PairingCipherSerParameter ciphertext_user1_org1 = engine.encrypt(publicKey, topLayerAdmin,
					e_num_user1_org1);
			ciphertextMap.put("user1_org1", ciphertext_user1_org1);

			// user2_org1 collect, encrypt and report data
			String num_user2_org1 = "21";
			Element e_num_user2_org1 = PairingUtils.mapNumStringToElement(pairing, num_user2_org1, PairingGroupType.GT);
			logger.info("e_num_user2_org1:" + e_num_user2_org1);
			PairingCipherSerParameter ciphertext_user2_org1 = engine.encrypt(publicKey, topLayerAdmin,
					e_num_user2_org1);
			ciphertextMap.put("user2_org1", ciphertext_user2_org1);

			// org1 aggregator aggregate the ciphertext of user1_org1 and user2_org1
			PairingCipherSerParameter ciphertext_org1 = engine.add(publicKey, ciphertextMap);

			// if org1 aggregator knows the secretKey, he can conduct the Decryption
			Element e_num_org1 = engine.decrypt(secretKey, topLayerAdmin, ciphertext_org1);
			logger.info("e_num_org1      :" + e_num_org1);
			try {
				// IBEHE(a*b) = IBEHE(a)+IBEHE(b)
				assertTrue(e_num_org1.isEqual(e_num_user1_org1.mul(e_num_user2_org1)));
				logger.info(engine.getEngineName() + " possesses multiplicative homomorphism!");
			} catch (Exception e) {
				logger.info(engine.getEngineName() + " homomorphism test failed!");
				logger.info("" + e.getLocalizedMessage());
			}
			// -----------------------------------------------------------------------------------------------------------
			// user1_org2 collect, encrypt and report data
//			String num_user1_org2 = "12";
//			Element e_num_user1_org2 = PairingUtils.mapNumStringToElement(pairing, num_user1_org2, PairingGroupType.GT);
//			PairingCipherSerParameter ciphertext_user1_org2 = engine.encrypt(publicKey, topLayerAdmin,
//					e_num_user1_org2);
//
//			// user2_org2 collect, encrypt and report data
//			String num_user2_org2 = "22";
//			Element e_num_user2_org2 = PairingUtils.mapNumStringToElement(pairing, num_user2_org2, PairingGroupType.GT);
//			PairingCipherSerParameter ciphertext_user2_org2 = engine.encrypt(publicKey, topLayerAdmin,
//					e_num_user2_org2);

		} catch (InvalidCipherTextException e) {
			logger.info("Valid decryption test failed, " + "secret key identity  = " + topLayerAdmin + ", "
					+ "ciphertext identity = " + topLayerAdmin);
			logger.info(e.getLocalizedMessage());
		}
	}
}
