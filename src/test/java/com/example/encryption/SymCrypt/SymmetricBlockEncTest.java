/**
 * 
 */
package com.example.encryption.SymCrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Test;

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
 * @Description: TODO(test the symmetric block encryption algorithm)
 */
public class SymmetricBlockEncTest {

	@Ignore
	@Test
	public void testAESString() {
		String key = "6206c34e2186e752c74e6df32ab8fa5b";
		String iv = "00e5d201c2c2acbff8154861242ba0c4";
		String iv_p = "00e5d201c2c2acbff8154861242ba0c5";
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
		plaintext_p = new String(SymmetricBlockEnc.dec_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv_p), ciphertext_p));
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
		plaintext_p = new String(SymmetricBlockEnc.dec_AES(Mode.CFB, Hex.decode(key), Hex.decode(iv_p), ciphertext_p));
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
		plaintext_p = new String(SymmetricBlockEnc.dec_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv_p), ciphertext_p));
		StdOut.println("Decrypted Plaintext = " + plaintext_p);
		StdOut.println();
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
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
