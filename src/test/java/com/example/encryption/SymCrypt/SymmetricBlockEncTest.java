/**
 * 
 */
package com.example.encryption.SymCrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.SymCrypt.SymmetricBlockEnc;
import cn.edu.ncepu.crypto.encryption.SymCrypt.SymmetricBlockEnc.Mode;
import edu.princeton.cs.algs4.StdOut;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 23, 2020 4:09:41 PM
 * @ClassName SymmetricBlockEncTest
 * @Description:  (test the symmetric block encryption algorithm)
 */
public class SymmetricBlockEncTest {
	private static final Logger logger = LoggerFactory.getLogger(SymmetricBlockEncTest.class);

	@Ignore
	@Test
	public void testAESString() {
		try {
			final String key = "6206c34e2186e752c74e6df32ab8fa5b";
			final String iv = "00e5d201c2c2acbff8154861242ba0c4";
			final String iv_p = "00e5d201c2c2acbff8154861242ba0c5";
			String message;
			byte[] ciphertext, ciphertext_p;
			String plaintext, plaintext_p;

			// Test ECB Mode
			StdOut.println("Test AES with ECB Mode.");
			message = "Message";
			StdOut.println("Message = " + message);
			ciphertext = SymmetricBlockEnc.enc_AES(Mode.ECB, Hex.decode(key), null, message.getBytes());

			StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext));
			plaintext = new String(SymmetricBlockEnc.dec_AES(Mode.ECB, Hex.decode(key), null, ciphertext));
			StdOut.println("Decrypted Plaintext = " + plaintext);
			StdOut.println();

			// Test CBC Mode
			StdOut.println("Test AES with CBC Mode.");
			message = "Message";
			StdOut.println("Message = " + message);
			// Test for Correctness
			ciphertext = SymmetricBlockEnc.enc_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv), message.getBytes());
			StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext));
			plaintext = new String(SymmetricBlockEnc.dec_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv), ciphertext));
			StdOut.println("Decrypted Plaintext = " + plaintext);
			// Test for Encryption with distinct IV
			ciphertext_p = SymmetricBlockEnc.enc_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv_p), message.getBytes());
			StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext_p));
			plaintext_p = new String(
					SymmetricBlockEnc.dec_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv_p), ciphertext_p));
			StdOut.println("Decrypted Plaintext = " + plaintext_p);
			StdOut.println();

			// Test CFB Mode
			StdOut.println("Test AES with CFB Mode.");
			message = "Message";
			StdOut.println("Message = " + message);
			// Test for Correctness
			ciphertext = SymmetricBlockEnc.enc_AES(Mode.CFB, Hex.decode(key), Hex.decode(iv), message.getBytes());
			StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext));
			plaintext = new String(SymmetricBlockEnc.dec_AES(Mode.CFB, Hex.decode(key), Hex.decode(iv), ciphertext));
			StdOut.println("Decrypted Plaintext = " + plaintext);
			// Test for Encryption with distinct IV
			ciphertext_p = SymmetricBlockEnc.enc_AES(Mode.CFB, Hex.decode(key), Hex.decode(iv_p), message.getBytes());
			StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext_p));
			plaintext_p = new String(
					SymmetricBlockEnc.dec_AES(Mode.CFB, Hex.decode(key), Hex.decode(iv_p), ciphertext_p));
			StdOut.println("Decrypted Plaintext = " + plaintext_p);
			StdOut.println();

			// Test OFB Mode
			StdOut.println("Test AES with OFB Mode.");
			message = "Message";
			StdOut.println("Message = " + message);
			// Test for Correctness
			ciphertext = SymmetricBlockEnc.enc_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv), message.getBytes());
			StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext));
			plaintext = new String(SymmetricBlockEnc.dec_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv), ciphertext));
			StdOut.println("Decrypted Plaintext = " + plaintext);
			// Test for Encryption with distinct IV
			ciphertext_p = SymmetricBlockEnc.enc_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv_p), message.getBytes());
			StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext_p));
			plaintext_p = new String(
					SymmetricBlockEnc.dec_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv_p), ciphertext_p));
			StdOut.println("Decrypted Plaintext = " + plaintext_p);
			StdOut.println();

			StdOut.println("Test AES with CBC Mode realized through BouncyCastle.");
			message = "Message";
			StdOut.println("Message = " + message);

			// Test for Correctness
			// sender send [IV,ciphertext] to receiver
			// generate random 16 bytes initialization vector
			SecureRandom sr = SecureRandom.getInstanceStrong();
			byte[] randIV = sr.generateSeed(16);
			ciphertext = SymmetricBlockEnc.enc_dec_AES_BC(true, Mode.CBC, key.getBytes(StandardCharsets.UTF_8), randIV,
					message.getBytes(StandardCharsets.UTF_8));
			StdOut.println("Encrypted Base64 Ciphertext = " + Base64.getEncoder().encodeToString(ciphertext));
			byte[] transmission = SymmetricBlockEnc.concat(randIV, ciphertext);
			// receiver receive [IV,ciphertext] frome sender
			randIV = new byte[16];
			ciphertext = new byte[transmission.length - 16];
			System.arraycopy(transmission, 0, randIV, 0, 16);
			System.arraycopy(transmission, 16, ciphertext, 0, ciphertext.length);
			plaintext = new String(
					SymmetricBlockEnc.enc_dec_AES_BC(false, Mode.CBC, key.getBytes(StandardCharsets.UTF_8), randIV, ciphertext),
                    StandardCharsets.UTF_8);
			StdOut.println("Decrypted Plaintext = " + plaintext);
			// Test for Encryption with distinct IV
			ciphertext_p = SymmetricBlockEnc.enc_dec_AES_BC(true, Mode.CBC, Hex.decode(key), Hex.decode(iv_p),
					message.getBytes());
			StdOut.println("Encrypted Hex Ciphertext = " + Hex.toHexString(ciphertext_p));
			plaintext_p = new String(
					SymmetricBlockEnc.enc_dec_AES_BC(false, Mode.CBC, Hex.decode(key), Hex.decode(iv_p), ciphertext_p));
			StdOut.println("Decrypted Plaintext = " + plaintext_p);
			StdOut.println();
		} catch (DataLengthException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			logger.error(e.getLocalizedMessage());
		} catch (NoSuchPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalBlockSizeException e) {
			logger.error(e.getLocalizedMessage());
		} catch (BadPaddingException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalStateException e) {
			logger.error(e.getLocalizedMessage());
		} catch (InvalidCipherTextException e) {
			logger.error(e.getLocalizedMessage());
		}
	}

	@Ignore
	@Test
	public void testAESFile() {
		try {
			String key = "6206c34e2186e752c74e6df32ab8fa5b";
			String iv = "00e5d201c2c2acbff8154861242ba0c4";
			File fileIn = new File("src/test/java/com/example/encryption/SymCrypt/test.pdf");
			File fileEnc = new File("src/test/java/com/example/encryption/SymCrypt/test.enc");
			File fileDec = new File("src/test/java/com/example/encryption/SymCrypt/test.dec");
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileEnc);

			SymmetricBlockEnc.enc_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv), in, out);
			in.close();
			out.close();

			in = new FileInputStream(fileEnc);
			out = new FileOutputStream(fileDec);

			SymmetricBlockEnc.dec_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv), in, out);
			in.close();
			out.close();
		} catch (FileNotFoundException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		} catch (DataLengthException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
