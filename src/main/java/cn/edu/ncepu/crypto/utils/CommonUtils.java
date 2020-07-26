/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
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

	private static final Logger logger = LoggerFactory.getLogger(CommonUtils.class);
	private static final int BUFFER_SIZE = 1024; // char
	private static final int MESSAGE_SIZE = 128;// byte

	/**
	 * TODO convert Hex or Base64 encoded "String" public or private Key to "PublicKey" or "PrivateKey"
	 * @param isECPublicKey
	 * @param enctype should be "base64" or "Hex"
	 * @param key
	 * @param algorithm
	 * @return 
	 * @throws DecoderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static Key string2ECKey(Boolean isECPublicKey, String enctype, String key, String algorithm)
			throws DecoderException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (!(enctype.equalsIgnoreCase("Base64") || enctype.equalsIgnoreCase("Hex"))) {
			throw new IllegalArgumentException("enctype should be 'Base64' or 'Hex'");
		}
		Key ecKey = null;
		byte[] bytes = null;
		if (enctype.equalsIgnoreCase("Base64")) {
			bytes = Hex.decodeHex(key);
		} else {
			bytes = Base64.getDecoder().decode(key);
		}
		EncodedKeySpec keySpec = null;
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		if (isECPublicKey) {
			// PublicKey is specific encoded as X.509 standard
			keySpec = new X509EncodedKeySpec(bytes);
			ecKey = keyFactory.generatePublic(keySpec);
		} else {
			// PrivateKey is specific encoded as PKCS #8 standard
			keySpec = new PKCS8EncodedKeySpec(bytes);
			ecKey = keyFactory.generatePrivate(keySpec);
		}
		return ecKey;
	}

	/**
	 * TODO print the input byte stream as char stream line
	 * @param inputStream
	 * @throws IOException
	 */
	public static void printInputStream(InputStream inputStream) throws IOException {
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
	}

	/**
	 * ODO(execute shell command through java method)
	 * @param command
	 * @param workDir
	 * @return the output of shell command
	 * @throws Exception 
	 */
	public static void callCMD(String command, String workDir) throws Exception {
		File dir = null;
		if (null != workDir) {
			dir = new File(workDir);
		}
		String[] envp = null; // String[] envp = { "val=1", "call=Bash Shell" };
		Process process = Runtime.getRuntime().exec(command, envp, dir);
		int exitValue = process.waitFor();
		if (0 != exitValue) {
			printInputStream(process.getInputStream());
			throw new Exception("call shell failed! error code is :" + exitValue);
		}
		printInputStream(process.getInputStream());
	}

	/**
	 * TODO(execute shell command array through java method)
	 * @param cmdArray
	 * @param workDir
	 * @return the output of shell command
	 * @throws Exception 
	 */
	public static void callCMD(String[] cmdArray, String workDir) throws Exception {
		File dir = null;
		if (null != workDir) {
			dir = new File(workDir);
		}
		String[] envp = null; // String[] envp = { "val=1", "call=Bash Shell" };
		Process process = Runtime.getRuntime().exec(cmdArray, envp, dir);
		int exitValue = process.waitFor();
		if (0 != exitValue) {
			printInputStream(process.getInputStream());
			throw new Exception("call shell failed! error code is :" + exitValue);
		}
		printInputStream(process.getInputStream());
	}

	/**
	 * TODO(execute shell command through java method)
	 * @param shell
	 * @param workDir
	 * @return the output of shell command
	 * @throws Exception 
	 */
	public static void callScript(String script, String args, String workDir) throws Exception {
		String command = "sh " + script + " " + args;
		File dir = null;
		if (null != workDir) {
			dir = new File(workDir);
		}
		String[] envp = null; // String[] evnp = { "val=1", "call=Bash Shell" };
		Process process = Runtime.getRuntime().exec(command, envp, dir);
		int exitValue = process.waitFor();
		if (0 != exitValue) {
			printInputStream(process.getInputStream());
			throw new Exception("call shell failed! error code is :" + exitValue);
		}
		printInputStream(process.getInputStream());
	}

	/**
	 * TODO(read bytes from binary file(e.g., PEM, DER))
	 * @param pathName path name of the binary file
	 * @return 
	 * @throws IOException 
	 */
	public static byte[] readBytesFromFile(String pathName) throws IOException {
		FileInputStream fis = new FileInputStream(pathName);
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int readCount;
		byte[] data = new byte[BUFFER_SIZE];
		while ((readCount = fis.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, readCount);
		}
		buffer.flush();
		fis.close();
		return buffer.toByteArray();
	}

	/**
	 * TODO(write bytes to binary file(e.g., PEM, DER))
	 * @param pathName path name of the binary file
	 * @param bytes 参数描述
	 * @throws IOException 
	 */
	public static void writeBytesToFile(String pathName, byte[] bytes) throws IOException {
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
	}

	/**
	 * TODO(save PublicKey or PrivateKey as PEM file)
	 * @param key should be PublicKey or PrivateKey which is the subclass of Key.
	 * @param filePath the complete file Path for PEM file to store
	 * @throws IOException 
	 * @throws Exception
	 */
	public static void saveKeyAsPEM(Key key, String pathName) throws IOException {
		boolean isPublicKey = key instanceof PublicKey;
		if (isPublicKey) {
			key = (PublicKey) key;
		} else {
			key = (PrivateKey) key;
		}
		// PrivateKey.getEncode() return PKCS #8 format and DER encoded bytes
		// PublicKey.getEncode() return X.509 format and DER encoded bytes
		String content = Base64.getEncoder().encodeToString(key.getEncoded());
		File file = new File(pathName);
		// if file does not exists, then create it
		if (!file.exists()) {
			file.createNewFile();
		}
		RandomAccessFile randomAccessFile = new RandomAccessFile(file, "rw");
		if (isPublicKey) {
			randomAccessFile.write("-----BEGIN PUBLIC KEY-----\n".getBytes());
		} else {
			randomAccessFile.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
		}
		int i = 0;
		for (; i < (content.length() - content.length() % 64); i += 64) {
			randomAccessFile.write(content.substring(i, i + 64).getBytes());
			randomAccessFile.write('\n');
		}
		randomAccessFile.write(content.substring(i, content.length()).getBytes());
		randomAccessFile.write('\n');
		if (isPublicKey) {
			randomAccessFile.write("-----END PUBLIC KEY-----\n".getBytes());
		} else {
			randomAccessFile.write("-----END PRIVATE KEY-----\n".getBytes());
		}
		randomAccessFile.close();
	}

	/**
	 * TODO(save PublicKey or PrivateKey as DER file)
	 * @param key should be PublicKey or PrivateKey which is the subclass of Key.
	 * @param pathName the complete file Path for DER file to store
	 * @throws IOException 
	 */
	public static void saveKeyAsDER(Key key, String pathName) throws IOException {
		boolean isPublicKey = key instanceof PublicKey;
		if (isPublicKey) {
			key = (PublicKey) key;
		} else {
			key = (PrivateKey) key;
		}
		// PrivateKey.getEncode() return PKCS #8 format and DER encoded bytes
		// Public.getEncode() return X.509 format and DER encoded bytes
		byte[] encodedKey = key.getEncoded();
		writeBytesToFile(pathName, encodedKey);
	}

	/**
	 * TODO(load Type PublicKey or PrivateKey from PEM key file)
	 * @param isPublicKey
	 * @param algorithm
	 * @param pathName pathName of PEM key file.
	 * @return Key PublicKey or PrivateKey
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static Key loadKeyFromPEM(boolean isPublicKey, String algorithm, String pathName)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(pathName);
		if (null == file || !file.isFile()) {
			throw new IllegalArgumentException("file \"" + file.getPath() + "\" do not exists");
		}
		String content = "";
		String pemPublicKey = null;
		RandomAccessFile randomAccessFile = new RandomAccessFile(file, "r");
		String line = null;
		while ((line = randomAccessFile.readLine()) != null) {
			content = content.concat(line);
		}
		if (isPublicKey) {
			pemPublicKey = content.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
		} else {
			pemPublicKey = content.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
		}
		randomAccessFile.close();

		Key key = null;
		byte[] encodedKey = Base64.getDecoder().decode(pemPublicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		EncodedKeySpec keySpec = null;
		if (isPublicKey) {
			// PublicKey is specific encoded as X.509 standard
			keySpec = new X509EncodedKeySpec(encodedKey);
			key = keyFactory.generatePublic(keySpec);
		} else {
			// PrivateKey is specific encoded as PKCS #8 standard
			keySpec = new PKCS8EncodedKeySpec(encodedKey);
			key = keyFactory.generatePrivate(keySpec);
		}
		return key;
	}

	/**
	 * TODO(load Type PublicKey or PrivateKey from DER key file)
	 * @param isPublicKey
	 * @param algorithm
	 * @param pathName pathName of DER key file.
	 * @return PublicKey or PrivateKey
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static Key loadKeyFromDER(boolean isPublicKey, String algorithm, String pathName)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(pathName);
		if (null == file || !file.isFile()) {
			throw new IllegalArgumentException("file \"" + file.getPath() + "\" do not exists");
		}
		Key ecKey = null;
		byte[] encodedKey = CommonUtils.readBytesFromFile(pathName);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		EncodedKeySpec keySpec = null;
		if (isPublicKey) {
			// PublicKey is specific encoded as X.509 standard
			keySpec = new X509EncodedKeySpec(encodedKey);
			ecKey = keyFactory.generatePublic(keySpec);
		} else {
			// PrivateKey is specific encoded as PKCS #8 standard
			keySpec = new PKCS8EncodedKeySpec(encodedKey);
			ecKey = keyFactory.generatePrivate(keySpec);
		}
		return ecKey;
	}

	/**
	 * TODO hash the string content using the specific algorithm
	 * @param content
	 * @param algorithm
	 * @return hex encoded hash string
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException 参数描述
	 */
	public static String hash(String content, String algorithm) {
		try {
			return CommonUtils.encodeHexString(hash(content.getBytes("UTF-8"), algorithm));
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getLocalizedMessage());
		}
		return null;
	}

	/**
	 * TODO(generate hash digest according to the specific hash algorithm)
	 * @param content: content waits to be hashed
	 * @param algorithm: specific Hash algorithm, including "MD2, MD5, SHA-1, SHA-256, SHA-512"...
	 * @return 参数描述
	 * @throws NoSuchAlgorithmException 
	 * @throws UnsupportedEncodingException 
	 */
	public static byte[] hash(byte[] content, String algorithm) {
		// Java标准库的java.security包提供了一种标准机制，允许第三方提供商无缝接入。
		// 我们要使用BouncyCastle提供的RipeMD160算法，需要先把BouncyCastle注册一下。
		// 注册只需要在启动时进行一次，后续就可以使用BouncyCastle提供的所有哈希算法和加密算法。
		Security.addProvider(new BouncyCastleProvider());
		final int N = (content.length - content.length % BUFFER_SIZE) / BUFFER_SIZE;
		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance(algorithm);
			// update input repeatly
			byte[] subContent = new byte[BUFFER_SIZE];
			int i = 0;
			for (; i < N; i++) {
				System.arraycopy(content, i * BUFFER_SIZE, subContent, 0, BUFFER_SIZE);
				messageDigest.update(subContent);
			}
			subContent = new byte[content.length % BUFFER_SIZE];
			System.arraycopy(content, i * BUFFER_SIZE, subContent, 0, subContent.length);
			messageDigest.update(subContent);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		}
		return messageDigest.digest();
	}

	/**
	 * TODO(function the same as org.apache.commons.codec.binary.Hex.encodeHexString)
	 * @param bytes bytes waits to be encoded to Hex(Base 16)
	 * @return 参数描述
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
	 * TODO(function the same as org.apache.commons.codec.binary.Hex.decodeHex)
	 * @param hexdata Hex string waits to be decoded
	 * @return
	 * @throws Exception 参数描述
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
	 * TODO(encode the url into %XX like format)
	 * @param content
	 * @return 参数描述
	 * @throws UnsupportedEncodingException 
	 */
	public static String encodeURLString(String content) throws UnsupportedEncodingException {
		return URLEncoder.encode(content, "UTF-8");
	}

	/**
	 * TODO(decode %XX like URL)
	 * @param content
	 * @return 参数描述
	 * @throws UnsupportedEncodingException 
	 */
	public static String decodeURL(String content) throws UnsupportedEncodingException {
		return URLDecoder.decode(content, "UTF-8");
	}

	/**
	    * 获得私钥
	    * 
	    * @param privateKey
	    * @param algorithm
	    * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	    */
	public static PrivateKey getPrivateKey(byte[] privateKey, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePrivate(pkcs8KeySpec);
	}

	/**
	 * 获得公钥
	 * 
	 * @param publicKey
	 * @param algorithm
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static PublicKey getPublicKey(byte[] publicKey, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePublic(keySpec);
	}

	/**
	 * 检查加解密操作模式
	 * 
	 * @param opmode
	 */
	public static void checkOpMode(int opmode) {
		if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE)
			throw new IllegalArgumentException(
					"opmode invalid, it should be Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE");
	}

	/**
	 * 签名
	 * 
	 * @param data
	 * @param privateKey
	 * @param signatureAlgorithm
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static byte[] sign(byte[] data, PrivateKey privateKey, String signatureAlgorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	/**
	 * 验签
	 * 
	 * @param data
	 * @param sign
	 * @param publicKey
	 * @param signatureAlgorithm
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static boolean verify(byte[] data, byte[] sign, PublicKey publicKey, String signatureAlgorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(sign);
	}

	/**
	 * 按单部分操作加密或解密数据，或者结束一个多部分操作
	 * 
	 * @param data
	 * @param cipher
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] doFinal(byte[] data, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal(data);
	}

	/**
	 * 初始化密钥
	 * 
	 * @param algorithm
	 * @param keySize
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static KeyPair initKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyPairGen.initialize(keySize, random);
		return keyPairGen.generateKeyPair();
	}

	/**
	 * TODO(get specific elliptic curve key pairs for ecdsa)
	 * @param param
	 * @return KeyPair
	 * @return the generated key pair
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public static KeyPair initKey(String algorithm, String curve)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		// specific the elliptic curve using stdName, including
		// "prime256v1、secp256r1、nistp256、secp256k1".
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curve);
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		// set specific parameters
		keyPairGenerator.initialize(ecGenParameterSpec, random);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * 初始化密钥
	 * 
	 * @param algorithm
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static SecretKey initKey(String algorithm) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey;
	}

	public static byte[] xor(byte[] a, byte[] b) {
//		byte[] result = new byte[Math.min(a.length, b.length)];
//		for (int i = 0; i < result.length; i++) {
//			result[i] = (byte) (((int) a[i]) ^ ((int) b[i]));
//		}
		int aLen = a.length;
		int bLen = b.length;
		byte[] result = new byte[Math.max(aLen, bLen)];
		int i = aLen - 1, j = bLen - 1;
		for (int k = result.length - 1; i >= 0 && j >= 0; i--, j--, k--) {
			result[k] = (byte) (((int) a[i]) ^ ((int) b[j]));
		}
		if (aLen > bLen) {
			for (int k = i; k >= 0; k--) {
				result[k] = a[k];
			}
		} else {
			for (int k = j; k >= 0; k--) {
				result[k] = b[k];
			}
		}
		return result;
	}

	// 把一个byte[] 分拆成每段MESSAGE_SIZE字节的数组List
	/**
	 * TODO slice  byte array into list with size MESSAGE_SIZE byte each element in the list;
	 * @param message
	 * @return
	 */
	public static ArrayList<byte[]> slice(byte[] message) {
		ArrayList<byte[]> list = new ArrayList<byte[]>();
		// boxCount the size of list
		int boxCount = ((message.length % MESSAGE_SIZE) == 0) ? (message.length / MESSAGE_SIZE)
				: ((message.length / MESSAGE_SIZE) + 1);
		for (int i = 0; i < boxCount - 1; ++i) {
			list.add(Arrays.copyOfRange(message, i * MESSAGE_SIZE, (i + 1) * MESSAGE_SIZE));
		}
		list.add(Arrays.copyOfRange(message, (boxCount - 1) * MESSAGE_SIZE, message.length));
		return list;
	}

	/**
	 * TODO splice list as single byte array
	 * @param byteMessage
	 * @return 参数描述
	 */
	public static byte[] splice(ArrayList<byte[]> byteMessage) {
		int boxCount = byteMessage.size();
		// byteSum the number of total bytes
		int byteSum = (MESSAGE_SIZE * (boxCount - 1)) + byteMessage.get(boxCount - 1).length;
		byte[] temp = new byte[byteSum];
		for (int i = 0; i < boxCount - 1; ++i) {
			for (int t = 0; t < MESSAGE_SIZE; ++t) {
				temp[i * MESSAGE_SIZE + t] = byteMessage.get(i)[t];
			}
		}
		for (int i = 0; i < byteMessage.get(boxCount - 1).length; ++i) {
			temp[MESSAGE_SIZE * (boxCount - 1) + i] = byteMessage.get(boxCount - 1)[i];
		}
		return temp;
	}

	public static String toString(ArrayList<byte[]> byteMessage) {
		return new String(splice(byteMessage));
	}
}
