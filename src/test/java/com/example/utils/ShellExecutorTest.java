/**
 * 
 */
package com.example.utils;

import java.io.IOException;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.utils.ShellExecutor;
import cn.edu.ncepu.crypto.utils.ShellExecutor.CommandTimeoutException;
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
	private static Logger logger = LoggerFactory.getLogger(ShellExecutorTest.class);
	private static String userDir = SysProperty.USER_DIR;

	@Ignore
	@Test
	public void testSimple() {
		try {
			logger.info(String.format("%d"), ShellExecutor.execute("pwd", userDir + "/scripts", null,
					(message, process) -> logger.info(message)));
		} catch (CommandTimeoutException | IOException | InterruptedException e) {
			logger.warn(e.getMessage(), e);
		}
	}

	@Ignore
	@Test
	public void test() {
		try {
			int result = ShellExecutor.execute(userDir + "/scripts/test.sh", null, null,
					(message, process) -> logger.info(String.format("Communication[1]: %s", message)),
					(message, process) -> logger.info(String.format("Communication[2]: %s", message)),
					(message, process) -> logger.info(String.format("Communication[3]: %s", message)));
			logger.info("" + result);
		} catch (CommandTimeoutException | IOException | InterruptedException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testMavenBuild() {
		try {
			logger.info("" + ShellExecutor.execute(userDir + "/scripts/testMvnInstall.sh", null, null,
					(message, process) -> logger.info(message)));
		} catch (CommandTimeoutException | IOException | InterruptedException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void simpleTest() {
		try {
			int exitValue = ShellExecutor.execute("./test.sh", System.getProperty("user.dir") + "/scripts", null,
					(message, process) -> logger.info(message));
			logger.info("exitValue: " + exitValue);
		} catch (ShellExecutor.CommandTimeoutException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InterruptedException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void complexCommandTest() {
		try {
			int exitValue = ShellExecutor.execute("ps -ef | grep java | grep -v grep", System.getProperty("user.dir"),
					null, (message, process) -> logger.info(message));
			logger.info("exitValue: " + exitValue);
		} catch (ShellExecutor.CommandTimeoutException e) {
			logger.info(e.getMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InterruptedException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
