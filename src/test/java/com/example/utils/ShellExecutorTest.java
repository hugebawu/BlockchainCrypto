/**
 * 
 */
package com.example.utils;

import org.junit.Ignore;
import org.junit.Test;

import cn.edu.ncepu.crypto.utils.ShellExecutor;
import cn.edu.ncepu.crypto.utils.SysProperty;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 26, 2020 4:12:11 PM
 * @ClassName ShellExecutorTest
 * @Description: TODO(这里用一句话描述这个方法的作用)
 */
public class ShellExecutorTest {
	private static String userDir = SysProperty.USER_DIR;

	@Ignore
	@Test
	public void testSimple() throws ShellExecutor.CommandTimeoutException {
		System.out.println(ShellExecutor.execute("pwd", userDir + "/scripts", null,
				(message, process) -> System.out.println(message)));
	}

	@Ignore
	@Test
	public void test() throws ShellExecutor.CommandTimeoutException {
		int result = ShellExecutor.execute(userDir + "/scripts/test.sh", null, null,
				(message, process) -> System.out.println(String.format("Communication[1]: %s", message)),
				(message, process) -> System.out.println(String.format("Communication[2]: %s", message)),
				(message, process) -> System.out.println(String.format("Communication[3]: %s", message)));
		System.out.println(result);
	}

	@Ignore
	@Test
	public void testMavenBuild() throws ShellExecutor.CommandTimeoutException {
		System.out.println(ShellExecutor.execute(userDir + "/scripts/testMvnInstall.sh", null, null,
				(message, process) -> System.out.println(message)));
	}

	@Ignore
	@Test
	public void simpleTest() {
		try {
			int exitValue = ShellExecutor.execute("./test.sh", System.getProperty("user.dir") + "/scripts", null,
					(message, process) -> System.out.println(message));
			System.out.println("exitValue: " + exitValue);
		} catch (ShellExecutor.CommandTimeoutException e) {
			System.out.println(e.getMessage());
		}
	}

	@Ignore
	@Test
	public void complexCommandTest() {
		try {
			int exitValue = ShellExecutor.execute("ps -ef | grep java | grep -v grep", System.getProperty("user.dir"),
					null, (message, process) -> System.out.println(message));
			System.out.println("exitValue: " + exitValue);
		} catch (ShellExecutor.CommandTimeoutException e) {
			System.out.println(e.getMessage());
		}
	}
}
