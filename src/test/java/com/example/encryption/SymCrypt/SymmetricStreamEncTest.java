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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.encryption.SymCrypt.SymmetricStreamEnc;
import cn.edu.ncepu.crypto.utils.SysProperty;
import edu.princeton.cs.algs4.StdOut;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 23, 2020 3:53:48 PM
 * @ClassName SymmetricStreamEncTest
 * @Description:  (test the symmetric stream encryption algorithm)
 */
public class SymmetricStreamEncTest {
	private static final Logger logger = LoggerFactory.getLogger(SymmetricStreamEncTest.class);
	final private static String USER_DIR = SysProperty.USER_DIR;

	@Ignore
	@Test
	public void testRC4String() {
		String key = "6206c34e2186e752c74e6df32ab8fa5b";
		StdOut.println("Test RC4.");
		String message = "Message";
		StdOut.println("Message = " + message);
		byte[] ciphertext = SymmetricStreamEnc.enc_RC4(Hex.decode(key), message.getBytes());
		StdOut.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext));
		String plaintext = new String(SymmetricStreamEnc.dec_RC4(Hex.decode(key), ciphertext));
		StdOut.println("Decrypted Plaintext = " + plaintext);
		StdOut.println();
	}

	@Ignore
	@Test
	public void testRC4File() {
		try {
			String key = "6206c34e2186e752c74e6df32ab8fa5b";
			File fileIn = new File(USER_DIR + "/elements/test.pdf");
			File fileEnc = new File(USER_DIR + "/elements/test.enc");
			File fileDec = new File(USER_DIR + "/elements/test.dec");
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileEnc);

			SymmetricStreamEnc.enc_RC4(Hex.decode(key), in, out);
			in.close();
			out.close();

			in = new FileInputStream(fileEnc);
			out = new FileOutputStream(fileDec);

			SymmetricStreamEnc.dec_RC4(Hex.decode(key), in, out);
			in.close();
			out.close();
		} catch (FileNotFoundException e) {
			logger.error(e.getLocalizedMessage());
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		}
	}
}
