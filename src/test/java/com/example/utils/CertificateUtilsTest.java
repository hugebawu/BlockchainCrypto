/**
 * 
 */
package com.example.utils;

import org.junit.Before;
import org.junit.Test;

import cn.edu.ncepu.crypto.utils.JCertificateUtils;
import junit.framework.TestCase;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 26, 2020 2:49:49 PM
 * @ClassName JCertificateUtilsTest
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
public class JCertificateUtilsTest extends TestCase {

	@Before
	public void init() {

	}

	@Test
	public void testExportCer() {
		JCertificateUtils.genKeyStore();
		JCertificateUtils.exportCer();
	}
}
