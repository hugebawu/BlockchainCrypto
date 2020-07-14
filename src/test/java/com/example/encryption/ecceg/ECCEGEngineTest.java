package com.example.encryption.ecceg;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.ecceg.ECCEGCipherText;
import cn.edu.ncepu.crypto.encryption.ecceg.ECCEGEngine;
import cn.edu.ncepu.crypto.encryption.ecceg.ECCEGKeyPair;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

@SuppressWarnings("rawtypes")
public class ECCEGEngineTest {
	private static Logger logger = LoggerFactory.getLogger(ECCEGEngineTest.class);
	private ECCEGEngine engine;

//	@Ignore
	@Test
	public void testECCEGEngineTest() {
		this.engine = ECCEGEngine.getInstance();
		PairingParameters pairingParams = PairingFactory
				.getPairingParameters(PairingUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		Pairing pairing = PairingFactory.getPairing(pairingParams);
		logger.info("--------------------系统建立阶段----------------------");
		engine.setup(pairing);
		logger.info("--------------------密钥提取阶段----------------------");
		ECCEGKeyPair eccegkeyPair = engine.extract();
		ZrElement privateKey = eccegkeyPair.getPrivateKey();
		logger.info("Private key: " + privateKey);
		CurveElement publicKey = eccegkeyPair.getPublicKey();
		logger.info("Public key: " + publicKey);
		logger.info("----------------------加密阶段-----------------------");
		String num_user1_org1 = "1";
		logger.info("num_user1_org1:" + num_user1_org1);
		CurveElement M_num_user1_org1 = (CurveElement) PairingUtils.mapNumStringToElement(pairing, num_user1_org1,
				PairingGroupType.G1);
		if (!M_num_user1_org1.isValid()) {
			throw new IllegalStateException("curve element is invalid");
		}
		logger.info("" + M_num_user1_org1);
		ECCEGCipherText cipherText_user1_org1 = engine.encrypt(M_num_user1_org1, publicKey);
		logger.info("-----------------------解密阶段----------------------");
		CurveElement decrypted_M = engine.decrypt(cipherText_user1_org1, privateKey);
		String plaintext_user1_Org1 = PairingUtils.mapElementToNumString(decrypted_M, PairingGroupType.G1);
		logger.info("plaintext_user1_Org1:" + plaintext_user1_Org1);
		assertTrue(plaintext_user1_Org1.equals(num_user1_org1));

//------------------------------------------------------------------------------------------------------
		String num_user2_org1 = "2";
		logger.info("num_user2_org1:" + num_user2_org1);
		CurveElement M_num_user2_org1 = (CurveElement) PairingUtils.mapNumStringToElement(pairing, num_user2_org1,
				PairingGroupType.G1);
		if (!M_num_user2_org1.isValid()) {
			throw new IllegalStateException("curve element is invalid");
		}
		ECCEGCipherText cipherText_user2_org1 = engine.encrypt(M_num_user2_org1, publicKey);
		logger.info("----------------------聚合阶段-----------------------");
		List<ECCEGCipherText> cipherTextList = new ArrayList<>();
		cipherTextList.add(cipherText_user1_org1);
		cipherTextList.add(cipherText_user2_org1);
		ECCEGCipherText cipherText_org1 = engine.add(cipherTextList);
		logger.info("----------------------验证聚合效果阶段-----------------------");
		// 验证 org1_U = (r1+r2)P 成功!
		ZrElement r1 = cipherText_user1_org1.getR();
		ZrElement r2 = cipherText_user2_org1.getR();
		CurveElement ciphertext_org1_U = cipherText_org1.getU();
		assertTrue(ciphertext_org1_U.equals(engine.getP().mulZn(r1.add(r2))));

		// 验证mapString2CurveElement(M1) + mapString2CurveElement(M2) =
		// mapString2CurveElement((new BigInteger(M1)+new BigInteger(M2)).toString())
		CurveElement expected_M = (CurveElement) PairingUtils.mapNumStringToElement(pairing, "3", PairingGroupType.G1);
		CurveElement addedM = M_num_user1_org1.add(M_num_user2_org1);
		// 验证不通过
		assertFalse(addedM.equals(expected_M));

		// 验证 org1_V = (M1+M2) + (r1+r2)Q 验证不通过
		CurveElement ciphertext_org1_V = cipherText_org1.getV();
		CurveElement added_V = addedM.add(publicKey.mulZn(r1.add(r2)));
		assertTrue(ciphertext_org1_V.equals(added_V));

		CurveElement ciphertext_org1_rQ = (CurveElement) cipherText_org1.getV().sub(addedM);
		assertTrue(ciphertext_org1_rQ.equals(publicKey.mulZn(r1.add(r2))));

		logger.info("-----------------------聚合数据解密阶段----------------------");
		CurveElement plaintext_Org1 = engine.decrypt(cipherText_org1, privateKey);
		String plaintextOrg1 = PairingUtils.mapElementToNumString(plaintext_Org1, PairingGroupType.G1);
		logger.info("plaintextOrg1:" + plaintextOrg1);
		String expectedText = (new BigInteger(num_user1_org1).add(new BigInteger(num_user2_org1))).toString();
		assertTrue(expectedText.equals(plaintextOrg1));
	}
}