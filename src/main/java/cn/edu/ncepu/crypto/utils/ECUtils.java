/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 19, 2020 5:06:57 PM
 * @ClassName ECUtils
 * @Description: TODO(common EC related  utils)
 */
public class ECUtils {
	private static final String EC_STRING = "EC";
	private static final String CURVE_NAME = "secp256k1";

	/**
	 * @Title: getKeyPair
	 * @Description: TODO(get specific elliptic curve key pairs for ecdsa)
	 * @param param
	 * @return KeyPair
	 * @return the generated key pair
	 * @throws
	 */
	public static KeyPair getECKeyPair() {
		KeyPair keyPair = null;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_STRING);
			// specific the elliptic curve using stdName, including
			// "prime256v1、secp256r1、nistp256、secp256k1".
			ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(CURVE_NAME);
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			// set specific parameters
			keyPairGenerator.initialize(ecGenParameterSpec, random);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return keyPair;
	}

	/**
	 * @Description: TODO(convert Hex encoded "String" public or private Key to "PublicKey" or "PrivateKey")
	 * @param key
	 * @return 参数描述
	 * @throws
	 */
	public static Key string2ECKey(Boolean isECPublicKey, String key) {
		Key ecKey = null;
		try {
			byte[] bytes = Hex.decodeHex(key);
			EncodedKeySpec keySpec = null;
			KeyFactory keyFactory = KeyFactory.getInstance(EC_STRING);
			if (isECPublicKey) {
				// PublicKey is specific encoded as X.509 standard
				keySpec = new X509EncodedKeySpec(bytes);
				ecKey = keyFactory.generatePublic(keySpec);
			} else {
				// PrivateKey is specific encoded as PKCS #8 standard
				keySpec = new PKCS8EncodedKeySpec(bytes);
				ecKey = keyFactory.generatePrivate(keySpec);
			}
		} catch (DecoderException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return ecKey;
	}

	/**
	 * @Description: TODO(save PublicKey or PrivateKey as PEM file)
	 * @param ecKey should be PublicKey or PrivateKey which is the subclass of Key.
	 * @param filePath the complete file Path for PEM file to store
	 * @throws Exception
	 * @throws
	 */
	public static void saveECKeyAsPEM(Key ecKey, String pathName) throws Exception {
		boolean isECPublicKey = ecKey instanceof PublicKey;
		if (isECPublicKey) {
			ecKey = (PublicKey) ecKey;
		} else {
			ecKey = (PrivateKey) ecKey;
		}
		// PrivateKey.getEncode() return PKCS #8 format and DER encoded bytes
		// PublicKey.getEncode() return X.509 format and DER encoded bytes
		String content = Base64.getEncoder().encodeToString(ecKey.getEncoded());
		File file = new File(pathName);
		// if file does not exists, then create it
		if (!file.exists()) {
			file.createNewFile();
		}
		try {
			RandomAccessFile randomAccessFile = new RandomAccessFile(file, "rw");
			if (isECPublicKey) {
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
			if (isECPublicKey) {
				randomAccessFile.write("-----END PUBLIC KEY-----\n".getBytes());
			} else {
				randomAccessFile.write("-----END PRIVATE KEY-----\n".getBytes());
			}
			randomAccessFile.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * @Description: TODO(save PublicKey or PrivateKey as DER file)
	 * @param ecKey should be PublicKey or PrivateKey which is the subclass of Key.
	 * @param pathName the complete file Path for DER file to store
	 * @throws
	 */
	public static void saveECKeyAsDER(Key ecKey, String pathName) {
		boolean isECPublicKey = ecKey instanceof PublicKey;
		if (isECPublicKey) {
			ecKey = (PublicKey) ecKey;
		} else {
			ecKey = (PrivateKey) ecKey;
		}
		// PrivateKey.getEncode() return PKCS #8 format and DER encoded bytes
		// Public.getEncode() return X.509 format and DER encoded bytes
		byte[] encodedKey = ecKey.getEncoded();
		CommonUtils.writeBytesToFile(pathName, encodedKey);
	}

	/**
	 * @throws Exception 
	 * @Description: TODO(load Type PublicKey or PrivateKey from PEM EC key file)
	 * @param isECPublicKey
	 * @param pathName pathName of PEM key file.
	 * @return Key PublicKey or PrivateKey
	 * @throws
	 */
	public static Key loadECKeyFromPEM(boolean isECPublicKey, String pathName) throws Exception {
		File file = new File(pathName);
		if (null == file || !file.isFile()) {
			throw new Exception("file \"" + file.getPath() + "\" do not exists");
		}
		String content = "";
		String pemPublicKey = null;
		try {
			RandomAccessFile randomAccessFile = new RandomAccessFile(file, "r");
			String line = null;
			while ((line = randomAccessFile.readLine()) != null) {
				content = content.concat(line);
			}
			if (isECPublicKey) {
				pemPublicKey = content.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----",
						"");
			} else {
				pemPublicKey = content.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----",
						"");
			}
			randomAccessFile.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		Key ecKey = null;
		try {
			byte[] encodedKey = Base64.getDecoder().decode(pemPublicKey);
			KeyFactory keyFactory = KeyFactory.getInstance(EC_STRING);
			EncodedKeySpec keySpec = null;
			if (isECPublicKey) {
				// PublicKey is specific encoded as X.509 standard
				keySpec = new X509EncodedKeySpec(encodedKey);
				ecKey = keyFactory.generatePublic(keySpec);
			} else {
				// PrivateKey is specific encoded as PKCS #8 standard
				keySpec = new PKCS8EncodedKeySpec(encodedKey);
				ecKey = keyFactory.generatePrivate(keySpec);
			}

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return ecKey;
	}

	/**
	 * @throws Exception 
	 * @Description: TODO(load Type PublicKey or PrivateKey from DER EC key file)
	 * @param isECPublicKey
	 * @param pathName pathName of DER key file.
	 * @return PublicKey or PrivateKey
	 * @throws
	 */
	public static Key loadECKeyFromDER(boolean isECPublicKey, String pathName) throws Exception {
		File file = new File(pathName);
		if (null == file || !file.isFile()) {
			throw new Exception("file \"" + file.getPath() + "\" do not exists");
		}
		Key ecKey = null;
		try {
			byte[] encodedKey = CommonUtils.readBytesFromFile(pathName);
			KeyFactory keyFactory = KeyFactory.getInstance(EC_STRING);
			EncodedKeySpec keySpec = null;
			if (isECPublicKey) {
				// PublicKey is specific encoded as X.509 standard
				keySpec = new X509EncodedKeySpec(encodedKey);
				ecKey = keyFactory.generatePublic(keySpec);
			} else {
				// PrivateKey is specific encoded as PKCS #8 standard
				keySpec = new PKCS8EncodedKeySpec(encodedKey);
				ecKey = keyFactory.generatePrivate(keySpec);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return ecKey;
	}

	/**
	 * @Description: TODO(print the content of DER or PEM ECKey file)
	 * @param isECPublicKey
	 * @param isDER
	 * @param pathName pathName for the DER or PEM, and PublicKey or PrivateKey file
	 * @throws
	 */
	public static void printECKeywithOpenssl(boolean isECPublicKey, boolean isDER, String pathName) {
		int indexofSlash = pathName.lastIndexOf("/");
		String filePath = pathName.substring(0, indexofSlash);
		String fileName = pathName.substring(indexofSlash + 1, pathName.length());
		String shell = "";
		if (isECPublicKey) {
			if (isDER) {
				shell = "openssl pkey -inform DER -pubin -in " + fileName + " -text";
			} else {
				shell = "openssl ec -in " + fileName + " -pubin -text -noout";
			}
		} else {
			if (isDER) {
				shell = "openssl pkey -inform DER -in " + fileName + " -text";
			} else {
				shell = "openssl ec -in " + fileName + " -text -noout";
			}
		}
		ArrayList<String> processList = CommonUtils.callCMD(shell, filePath);
		for (String line : processList) {
			System.out.println(line);
		}
	}

}
