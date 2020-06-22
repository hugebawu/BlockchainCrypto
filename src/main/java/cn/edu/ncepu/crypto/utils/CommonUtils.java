/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 20, 2020 11:34:12 PM
 * @ClassName CommonUtils
 * @Description: TODO(some common utils for java programme)
 */
public class CommonUtils {

	/**
	 * @Description: TODO(execute shell command through java method)
	 * @param shell
	 * @param workDir
	 * @return the output of shell command
	 * @throws
	 */
	public static ArrayList<String> callCMD(String shell, String workDir) {
		ArrayList<String> processList = new ArrayList<String>();
		try {
			File dir = null;
			if (null != workDir) {
				dir = new File(workDir);
			}
			String[] envp = null; // String[] envp = { "val=1", "call=Bash Shell" };
			Process process = Runtime.getRuntime().exec(shell, envp, dir);
			int exitValue = process.waitFor();
			if (0 != exitValue) {
				System.out.println("call shell failed! error code is :" + exitValue);
				System.exit(1);
			}
			// InputStreamReader turns byte stream to char stream ,while OutputStreamWriter
			// turns char stream to byte stream.
			InputStreamReader inputStreamReader = new InputStreamReader(process.getInputStream());
			// BufferedReader is expanded from Reader, provider common buffer methonds for
			// text read.
			BufferedReader input = new BufferedReader(inputStreamReader);
			String line = "";
			while ((line = input.readLine()) != null) {
				processList.add(line);
			}
			input.close();
		} catch (Exception e) {
			System.out.println("call shell failed!");
			e.printStackTrace();
		}
		return processList;
	}

	/**
	 * @Description: TODO(execute shell command through java method)
	 * @param shell
	 * @param workDir
	 * @return the output of shell command
	 * @throws
	 */
	public static ArrayList<String> callScript(String script, String args, String workDir) {
		ArrayList<String> processList = new ArrayList<String>();
		try {
			String command = "sh " + script + " " + args;
			File dir = null;
			if (null != workDir) {
				dir = new File(workDir);
			}
			String[] envp = null; // String[] evnp = { "val=1", "call=Bash Shell" };
			Process process = Runtime.getRuntime().exec(command, envp, dir);
			int exitValue = process.waitFor();
			if (0 != exitValue) {
				System.out.println("call shell failed! error code is :" + exitValue);
				System.exit(1);
			}
			// InputStreamReader turns byte stream to char stream ,while OutputStreamWriter
			// turns char stream to byte stream.
			InputStreamReader inputStreamReader = new InputStreamReader(process.getInputStream());
			// BufferedReader is expanded from Reader, provider common buffer methonds for
			// text read.
			BufferedReader input = new BufferedReader(inputStreamReader);
			String line = "";
			while ((line = input.readLine()) != null) {
				processList.add(line);
			}
			input.close();
		} catch (Exception e) {
			System.out.println("call shell failed!");
			e.printStackTrace();
		}
		return processList;
	}

	/**
	 * @Description: TODO(read bytes from binary file)
	 * @param pathName path name of the binary file
	 * @return 参数描述
	 * @throws
	 */
	public static byte[] readBytesFromFile(String pathName) {
		byte[] bytes = null;
		try {
			FileInputStream fis = new FileInputStream(pathName);
			final int BUFFER_SIZE = 1024;
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			int readCount;
			byte[] data = new byte[BUFFER_SIZE];
			while ((readCount = fis.read(data, 0, data.length)) != -1) {
				buffer.write(data, 0, readCount);
			}
			buffer.flush();
			bytes = buffer.toByteArray();
			fis.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return bytes;
	}

	public static void writeBytesToFile(String pathName, byte[] bytes) {
		try {
			File file = new File(pathName);
			FileOutputStream fos = new FileOutputStream(file);
			// if file does not exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}
			fos.write(bytes);
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
