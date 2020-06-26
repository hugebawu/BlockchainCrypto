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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private static Logger logger = LoggerFactory.getLogger(CommonUtils.class);

	public static void printShellOutput(InputStream inputStream) {
		try {
			// InputStreamReader turns byte stream to char stream ,while OutputStreamWriter
			// turns char stream to byte stream.
			InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
			// BufferedReader is expanded from Reader, provider common buffer methonds for
			// text read.
			BufferedReader input = new BufferedReader(inputStreamReader);
			String line = "";
			while ((line = input.readLine()) != null) {
				logger.info(line);
			}
			input.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * @Description: TODO(execute shell command through java method)
	 * @param shell
	 * @param workDir
	 * @return the output of shell command
	 * @throws
	 */
	public static void callCMD(String shell, String workDir) {
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
				printShellOutput(process.getInputStream());
				System.exit(1);
			}
			printShellOutput(process.getInputStream());
		} catch (Exception e) {
			System.out.println("call shell failed!");
			e.printStackTrace();
		}
	}

	/**
	 * @Description: TODO(execute shell command through java method)
	 * @param shell
	 * @param workDir
	 * @return the output of shell command
	 * @throws
	 */
	public static void callScript(String script, String args, String workDir) {
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
				printShellOutput(process.getInputStream());
				System.exit(1);
			}
			printShellOutput(process.getInputStream());
		} catch (Exception e) {
			System.out.println("call shell failed!");
			e.printStackTrace();
		}
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
			// overwrite the file
			FileOutputStream fos = new FileOutputStream(file, false);
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
		// Java标准库的java.security包提供了一种标准机制，允许第三方提供商无缝接入。
		// 我们要使用BouncyCastle提供的RipeMD160算法，需要先把BouncyCastle注册一下。
		// 注册只需要在启动时进行一次，后续就可以使用BouncyCastle提供的所有哈希算法和加密算法。
		Security.addProvider(new BouncyCastleProvider());
		String hexHash = null;
		final int BUFFER_SIZE = 1024;
		final int N = (content.length() - content.length() % BUFFER_SIZE) / BUFFER_SIZE;
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
			// update input repeatly
			int i = 0;
			for (; i < N; i++) {
				String subString = content.substring(i * BUFFER_SIZE, (i + 1) * BUFFER_SIZE);
				messageDigest.update(subString.getBytes("UTF-8"));
			}
			messageDigest.update(content.substring(i * BUFFER_SIZE, content.length()).getBytes("UTF-8"));
			hexHash = CommonUtils.encodeHexString(messageDigest.digest());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
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

	/**
	 * @Description: TODO(encode the url into %XX like format)
	 * @param content
	 * @return 参数描述
	 * @throws
	 */
	public static String encodeURLString(String content) {
		String encoded = null;
		try {
			return URLEncoder.encode(content, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return encoded;
	}

	/**
	 * @Description: TODO(decode %XX like URL)
	 * @param content
	 * @return 参数描述
	 * @throws
	 */
	public static String decodeURL(String content) {
		String decoded = null;
		try {
			return URLDecoder.decode(content, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return decoded;
	}
}
