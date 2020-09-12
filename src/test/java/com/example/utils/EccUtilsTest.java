package com.example.utils;

import cn.edu.ncepu.crypto.utils.EccUtils;
import cn.edu.ncepu.crypto.utils.SysProperty;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 27, 2020 12:04:49 AM
 * @ClassName EccUtilsTest
 * @Description: (这里用一句话描述这个方法的作用)
 */
@SuppressWarnings("unused")
public class EccUtilsTest {
	private static final Logger logger = LoggerFactory.getLogger(EccUtilsTest.class);
	private static final String USER_DIR = SysProperty.USER_DIR;
	private static final String CURVE_NAME = "secp256k1";

//	@Ignore
	@Test
	public void testPrintECKeyWithOpenssl() {
		logger.info("==================DER publicKey==================");
		try {
			EccUtils.printECKeywithOpenssl(true, true, USER_DIR + "/elements/ECPublicKey.der");
			logger.info("\n==================DER privateKey==================");
			EccUtils.printECKeywithOpenssl(false, true, USER_DIR + "/elements/ECPrivateKey.der");
			logger.info("\n");
			logger.info("==================PEM publicKey==================");
			EccUtils.printECKeywithOpenssl(true, false, USER_DIR + "/elements/ECPublicKey.pem");
			logger.info("\n==================PEM privateKey==================");
			EccUtils.printECKeywithOpenssl(false, false, USER_DIR + "/elements/ECPrivateKey.pem");
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
