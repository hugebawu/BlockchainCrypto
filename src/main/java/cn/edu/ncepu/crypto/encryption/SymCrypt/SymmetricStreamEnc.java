/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.SymCrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 23, 2020 3:42:09 PM
 * @ClassName SymmetricStreamEnc
 * @Description:  (流密码算法这里只实现了RC4算法，实际上Bouncy Castle里面实现了所有已经公开的流密码算法，
 * 但是RC4算法依然是流密码算法的主流。我们的单钥加密函数有两部分：对于任意byte[]的加密，以及对于任意inputstream的加密。
 * 这里要注意的是，inputstream的加密我们使用了格式化输出，而非传统的将加密结果直接写入outputstream。这么做的原因是，
 * 对于不同操作系统，其编码方式有所不同。在Windows下面，如果打开一个byte[]文件，那么系统会自动对文件进行可行的转换操作，
 * 而这种转换会导致错误的解密结果。使用格式化输出后，所有的输出都被编码成0x00-0xFF，这样就避免了上述的问题。
 * https://blog.csdn.net/liuweiran900217/article/details/38439875)
 */
public class SymmetricStreamEnc {
	private static final int DEFUALT_BLOCK_SIZE = 128;

	/**
	 *   RC4 file encryption method
	 * @param key
	 * @param plaintext
	 * @return 参数描述
	 */
	public static byte[] enc_RC4(byte[] key, byte[] plaintext) {
		// Make sure the validity of key, and plaintext
		if (key == null || plaintext == null) {
			throw new NullPointerException("key || plaintext is null");
		}
		KeyParameter kp = new KeyParameter(key);
		StreamCipher streamCipher = new RC4Engine();
		streamCipher.init(true, kp);

		byte[] ciphertext = new byte[plaintext.length];
		streamCipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
		return ciphertext;
	}

	/**
	 *   RC4 string decryption method
	 * @param key
	 * @param ciphertext
	 * @return 
	 */
	public static byte[] dec_RC4(byte[] key, byte[] ciphertext) {
		// Make sure the validity of key, and ciphertext
		if (key == null || ciphertext == null) {
			throw new NullPointerException("key || ciphertext is null");
		}
		KeyParameter kp = new KeyParameter(key);
		StreamCipher streamCipher = new RC4Engine();
		streamCipher.init(false, kp);

		byte[] plaintext = new byte[ciphertext.length];
		streamCipher.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
		return plaintext;
	}

	/**
	 *   RC4 file decryption method
	 * @param key
	 * @param in
	 * @param out 
	 * @throws IOException 
	 * @throws DataLengthException 
	 */
	public static void enc_RC4(byte[] key, InputStream in, OutputStream out) throws DataLengthException, IOException {
		// Make sure the validity of key, and plaintext
		if (key == null || in == null || out == null) {
			throw new NullPointerException("key || inputStream || outputStream is null");
		}
		KeyParameter kp = new KeyParameter(key);
		StreamCipher streamCipher = new RC4Engine();
		streamCipher.init(true, kp);
		int inBlockSize = DEFUALT_BLOCK_SIZE;
		int outBlockSize = DEFUALT_BLOCK_SIZE;
		byte[] inblock = new byte[inBlockSize];
		byte[] outblock = new byte[outBlockSize];
		int inL;
		byte[] rv = null;
		while ((inL = in.read(inblock, 0, inBlockSize)) > 0) {
			streamCipher.processBytes(inblock, 0, inL, outblock, 0);
			rv = Hex.encode(outblock, 0, inL);
			out.write(rv, 0, rv.length);
			out.write('\n');
		}
	}

	/**
	 *   RC4 file encryption method
	 * @param key
	 * @param in
	 * @param out
	 * @throws DataLengthException
	 * @throws IOException 
	 */
	public static void dec_RC4(byte[] key, InputStream in, OutputStream out) throws DataLengthException, IOException {
		// Make sure the validity of key, and ciphertext
		if (key == null || in == null || out == null) {
			throw new NullPointerException("key || inputStream || outputStream is null");
		}
		KeyParameter kp = new KeyParameter(key);
		StreamCipher streamCipher = new RC4Engine();
		streamCipher.init(false, kp);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		byte[] inblock = null;
		byte[] outblock = null;
		String rv = null;

		while ((rv = br.readLine()) != null) {
			inblock = Hex.decode(rv);
			outblock = new byte[DEFUALT_BLOCK_SIZE];
			streamCipher.processBytes(inblock, 0, inblock.length, outblock, 0);
			out.write(outblock, 0, inblock.length);
		}
	}
}
