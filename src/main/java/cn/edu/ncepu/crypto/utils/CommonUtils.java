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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
	 * @Description: TODO(read bytes from binary file(e.g., PEM, DER))
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

	/**
	 * @Description: TODO(write bytes to binary file(e.g., PEM, DER))
	 * @param pathName path name of the binary file
	 * @param bytes 参数描述
	 * @throws
	 */
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

	/**
	 * @Description: TODO(generate hash digest according to the specific hash algorithm)
	 * @param content content waits to be hashed
	 * @param algorithm specific Hash algorithm, including "MD2, MD5, SHA-1, SHA-256, SHA-512"...
	 * @return 参数描述
	 * @throws
	 */
	public static String genHash(String content, String algorithm) {
		String hexHash = null;
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
			hexHash = CommonUtils.encodeHexString(messageDigest.digest(content.getBytes()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return hexHash;
	}

	/**
	 * @Description: TODO(function the same as org.apache.commons.codec.binary.Hex.encodeHexString)
	 * @param bytes bytes waits to be encoded to Hex(Base 16)
	 * @return 参数描述
	 * @throws
	 */
	public static String encodeHexString(final byte[] data) {
		String hex = "";
		String tmp = "";
		final int len = data.length;
		for (int i = 0; i < len; i++) {
			tmp = Integer.toHexString(data[i] & 0XFF);
			if (1 == tmp.length()) {
				hex = hex + "0" + tmp;
			} else {
				hex = hex + tmp;
			}
		}
		return hex;
	}

	/**
	 * @Description: TODO(function the same as org.apache.commons.codec.binary.Hex.decodeHex)
	 * @param hexdata Hex string waits to be decoded
	 * @return
	 * @throws Exception 参数描述
	 * @throws
	 */
	public static byte[] decodeHex(String hexdata) throws Exception {
		char[] data = hexdata.toCharArray();
		final int len = data.length;
		if (len % 2 != 0) {
			throw new Exception("Odd number of characters.");
		}
		byte[] bytes = new byte[len >> 1];
		// two characters form the hex value.
		for (int i = 0, j = 0; j < len; i++) {
			int f = Character.digit(data[j], 16) << 4;
			j++;
			f = f | Character.digit(data[j], 16);
			j++;
			bytes[i] = (byte) (f & 0xFF);
		}
		return bytes;
	}
}
