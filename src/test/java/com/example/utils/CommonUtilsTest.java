/**
 * 
 */
package com.example.utils;

import java.util.ArrayList;

import cn.edu.ncepu.crypto.utils.CommonUtils;
import junit.framework.TestCase;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 21, 2020 12:08:45 AM
 * @ClassName CommonUtilsTest
 * @Description: TODO(test methods of CommonUtils)
 */
public class CommonUtilsTest extends TestCase {

	public static void testCallCMD() {
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

	public static void testCallScript() {
		String args = "1 2 3";
		ArrayList<String> processList = CommonUtils.callScript("test.sh", args,
				"/root/Documents/eclipse-workspace/BlockchainCrypto/src/test/java/com/example/utils");
		for (String line : processList) {
			System.out.println(line);
		}

	}
}
