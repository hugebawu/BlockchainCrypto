/**
 * 
 */
package com.example.utils;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.DecoderException;
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
		CommonUtils.callCMD(shell,
				"/root/Documents/eclipse-workspace/BlockchainCrypto/src/test/java/com/example/utils");
		shell = "ls -al";
		CommonUtils.callCMD(shell,
				"/root/Documents/eclipse-workspace/BlockchainCrypto/src/test/java/com/example/utils");
	}

	@Ignore
	@Test
	public void testCallScript() {
		String args = "1 2 3";
		CommonUtils.callScript("test.sh", args,
				"/root/Documents/eclipse-workspace/BlockchainCrypto/src/test/java/com/example/utils");
	}

	@Ignore
	@Test
	public void testGenHash() {
		String content = "HelloWorld";

		// utilize jdk
		String algorithm = "SHA256";
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
		try {
			// encode
			String hexdata = CommonUtils.encodeHexString(content.getBytes("UTF-8"));
			// decode
			String decoded = new String(Hex.decodeHex(hexdata));
			System.out.println("encoded Hex string: " + hexdata);
			System.out.println("decoded content " + decoded);
			assertEquals(content, decoded);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (DecoderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Ignore
	@Test
	public void testDecodeHex() {
		String content = "abc123!@#阿萨德'}|";
		System.out.println("initial content " + content);
		try {
			final String hexdata = Hex.encodeHexString(content.getBytes("UTF-8"));
			System.out.println("encoded Hex string: " + hexdata);
			String decoded = new String(CommonUtils.decodeHex(hexdata));
			System.out.println("decoded content " + decoded);
			assertEquals(content, decoded);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Ignore
	@Test
	public void testURLEncodeDecode() {
		// encode
		String encoded = CommonUtils.encodeURLString("中文!");
		System.out.println("URL encoded = " + encoded);
		// decode
		String decoded = CommonUtils.decodeURL(encoded);
		System.out.println("URL decoded = " + decoded);
	}

}
