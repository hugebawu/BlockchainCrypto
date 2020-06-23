/**
 * 
 */
package com.example.utils;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Ignore;
import org.junit.Test;

import cn.edu.ncepu.crypto.utils.CommonUtils;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 21, 2020 12:08:45 AM
 * @ClassName CommonUtilsTest
 * @Description: TODO(test methods of CommonUtils)
 */
public class CommonUtilsTest {

	@Ignore
	@Test
	public void testCallCMD() {
		String shell = "pwd";
		ArrayList<String> processList = CommonUtils.callCMD(shell,
				"/root/Documents/eclipse-workspace/BlockchainCrypto/src/test/java/com/example/utils");
		for (String line : processList) {
			System.out.println(line);
		}
		shell = "ls -al";
		processList = CommonUtils.callCMD(shell,
				"/root/Documents/eclipse-workspace/BlockchainCrypto/src/test/java/com/example/utils");
		for (String line : processList) {
			System.out.println(line);
		}
	}

	@Ignore
	@Test
	public void testCallScript() {
		String args = "1 2 3";
		ArrayList<String> processList = CommonUtils.callScript("test.sh", args,
				"/root/Documents/eclipse-workspace/BlockchainCrypto/src/test/java/com/example/utils");
		for (String line : processList) {
			System.out.println(line);
		}
	}

	@Ignore
	@Test
	public void testGenHahs() {
		String content = "abc123!@#阿萨德'}|";

		// utilize jdk
		String algorithm = "SHA-256";
		System.out.println("Hash Algorithm: " + algorithm);
		String hexHash = CommonUtils.genHash(content, algorithm);
		System.out.println("hex hash digest: " + hexHash);
		System.out.println("hex hash digest length: " + hexHash.length());

		// utilize third party library.
		String hash = DigestUtils.sha256Hex(content);
		assertEquals(hexHash, hash);
	}

	@Ignore
	@Test
	public void testEncodeHex() {
		String content = "abc123!@#阿萨德'}|";
		System.out.println("initial content " + content);
		final String hexdata = CommonUtils.encodeHexString(content.getBytes());
		System.out.println("encoded Hex string: " + hexdata);
		try {
			String decoded = new String(Hex.decodeHex(hexdata));
			System.out.println("decoded content " + decoded);
			assertEquals(content, decoded);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Ignore
	@Test
	public void testDecodeHex() {
		String content = "abc123!@#阿萨德'}|";
		System.out.println("initial content " + content);
		final String hexdata = Hex.encodeHexString(content.getBytes());
		System.out.println("encoded Hex string: " + hexdata);
		try {
			String decoded = new String(CommonUtils.decodeHex(hexdata));
			System.out.println("decoded content " + decoded);
			assertEquals(content, decoded);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
