/**
 * 
 */
package com.example.homomorphicencryption.eccegHE;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.homomorphicEncryption.CipherText;
import cn.edu.ncepu.crypto.homomorphicEncryption.HE;
import cn.edu.ncepu.crypto.homomorphicEncryption.eccegHE.ECElgamalHECipherText;
import cn.edu.ncepu.crypto.homomorphicEncryption.eccegHE.ECElgamalHEEngine;
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
 * @CreateData: Jul 11, 2020 7:26:24 PM
 * @ClassName ECElgamalHEEngineTest
 * @Description:  (这里用一句话描述这个方法的作用)
 */
public class ECElgamalHEEngineTest {
	private static Logger logger = LoggerFactory.getLogger(ECElgamalHEEngineTest.class);
	private PairingParameters pairingParams = null;
	private ECElgamalHEEngine engine;

	/**
	 *   测试ECElgamalHE的加密解密功能
	 */
	@Ignore
	@Test
	public void testECElgamalHE() {
		logger.info("start ECElgamalHE Testing \n");
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		Pairing pairing = PairingFactory.getPairing(pairingParams);
		this.engine = ECElgamalHEEngine.getInstance(pairing);
		// 动态代理，统计各个方法耗时
		HE identProxy = (HE) Proxy.newProxyInstance(ECElgamalHEEngine.class.getClassLoader(), new Class[] { HE.class },
				new TimeCountProxyHandle(engine));
		logger.info("--------------------系统建立阶段----------------------");
		identProxy.setup();
		logger.info("--------------------密钥提取阶段----------------------");
		Element d = identProxy.keyGen("");
		logger.info("----------------------加密阶段-----------------------");
		String message = "2";
		logger.info("plaintext: " + message);
		CipherText cipherText = identProxy.encrypt(message);
		logger.info("-----------------------解密阶段----------------------");
		String decrypted = identProxy.decrypt(d, cipherText);
		logger.info("decrypted: " + decrypted);
		try {
			assertTrue(message.equals(decrypted));
			logger.info("ECElgamalHE encryption and decryption test passed!");
		} catch (Exception e) {
			logger.info("ECElgamalHE encryption and decryption test failed!");
			logger.info("" + e.getLocalizedMessage());
		}
	}

//	@Ignore
	@Test
	public void testHomomorphismOfECElgamalHE() {
		pairingParams = PairingFactory.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		Pairing pairing = PairingFactory.getPairing(pairingParams);
		this.engine = ECElgamalHEEngine.getInstance(pairing);
		Map<String, CipherText> ciphertextMap = new LinkedHashMap<String, CipherText>();
		logger.info("--------------------系统建立阶段----------------------");
		engine.setup();
		logger.info("--------------------密钥提取阶段----------------------");
		Element d = engine.keyGen("");
		logger.info("----------------------加密阶段-----------------------");
		String num_user1_org1 = "11";
		Element e_num_user1_org1 = PairingUtils.mapNumStringToElement(pairing, num_user1_org1, PairingGroupType.G1);
		ECElgamalHECipherText ciphertext_user1_org1 = engine.encrypt(num_user1_org1);
		ciphertextMap.put("user1_org1", ciphertext_user1_org1);
		String num_user2_org1 = "12";
		Element e_num_user2_org1 = PairingUtils.mapNumStringToElement(pairing, num_user2_org1, PairingGroupType.G1);
		ECElgamalHECipherText ciphertext_user2_org1 = engine.encrypt(num_user2_org1);
		ciphertextMap.put("user2_org1", ciphertext_user2_org1);
		logger.info("--------------------数据聚合阶段----------------------");
		ECElgamalHECipherText ciphertext_org1 = (ECElgamalHECipherText) engine.eval(ciphertextMap);
		logger.info("--------------------密文验证阶段----------------------");
		// 验证r
		Element r1 = ciphertext_user1_org1.getR();
		Element r2 = ciphertext_user2_org1.getR();
		Element r12 = ciphertext_org1.getR();
		assertTrue(r12.isEqual(r1.add(r2)));

		// 验证U
		Element U12 = ciphertext_org1.getU();
		assertTrue(U12.isEqual(ciphertext_org1.getP().mulZn(r1.add(r2))));
		// 验证V
		Element V1 = ciphertext_user1_org1.getV();
		Element V2 = ciphertext_user2_org1.getV();
		Element V12 = ciphertext_org1.getV();
		assertTrue(V12.equals(V1.add(V2)));
		logger.info("-----------------------解密阶段----------------------");
		String decrypted = engine.decrypt(d, ciphertext_org1);
		logger.info("decrypted: " + decrypted);
		Element e_decrypted = PairingUtils.mapNumStringToElement(pairing, decrypted, PairingGroupType.G1);
		Element preNum = e_num_user1_org1.add(e_num_user2_org1);
		try {
			assertTrue(preNum.isEqual(e_decrypted));
			logger.info("ECElgamalHE possesses multiplicative homomorphism!");
		} catch (Exception e) {
			logger.info("ECElgamalHE homomorphism test failed!");
			logger.info("" + e.getLocalizedMessage());
		}
	}
}
