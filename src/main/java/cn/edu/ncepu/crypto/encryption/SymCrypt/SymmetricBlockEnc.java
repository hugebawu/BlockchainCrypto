/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.SymCrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 23, 2020 4:07:12 PM
 * @ClassName SymmetricBlockEnc
 * @Description: TODO(对于分组密码算法，这里只实现了AES（128bit, 192bit和256bit版本），我们实现了不同的工作模式。
 * 工作模式的控制由枚举类来完成。对于分组密码，其加密解密过程要稍微复杂一点，需要引入BufferedStream，不过大致的加密流程类似。)
 */
public class SymmetricBlockEnc {
	/**
	 * Algorithm         work mode              pad mode
	 * DES	56/64	     ECB/CBC/PCBC/CTR/...	NoPadding/PKCS5Padding/...
	   AES	128/192/256	 ECB/CBC/PCBC/CTR/...	NoPadding/PKCS5Padding/PKCS7Padding/...
	   IDEA	128	         ECB	                PKCS5Padding/PKCS7Padding/...
	 */

	public static final byte[] InitVector = { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x38, 0x37, 0x36, 0x35,
			0x34, 0x33, 0x32, 0x31 };

	public enum Mode {
		/**
		 * Electronic CodeBook Mode
		 */
		ECB,

		/**
		 * Cipher-Block Chaining Mode
		 */
		CBC,

		/**
		 * Cipher FeedBack Mode
		 */

		CFB,
		/**
		 * Output FeedBack Mode
		 */
		OFB,
	}

	// The default block size in bits (note: a multiple of 8)
	private static int DEFAULT_SIZE = 16;

	public static byte[] enc_AES(Mode mode, byte[] key, byte[] iv, byte[] plaintext) {
		// Make sure the validity of key, and plaintext
		assert (key != null && plaintext != null);
		// The valid key length is 16Bytes, 24Bytes or 32Bytes
		assert (key.length == 16 || key.length == 24 || key.length == 32);
		if (mode != Mode.ECB) {
			// The valid init vector is a no-none 16Bytes array
			assert (iv != null && iv.length == 16);
		}
		try {
			KeyParameter kp = new KeyParameter(key);
			BufferedBlockCipher b = null;
			switch (mode) {
			case ECB:
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(true, kp);
				break;
			case CBC:
				b = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
				b.init(true, new ParametersWithIV(kp, iv));
				break;
			case CFB:
				b = new PaddedBufferedBlockCipher(new CFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(true, new ParametersWithIV(kp, iv));
				break;
			case OFB:
				b = new PaddedBufferedBlockCipher(new OFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(true, new ParametersWithIV(kp, iv));
				break;
			default:
				// Default Mode is ECB Mode
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(true, kp);
				break;
			}
			byte[] enc = new byte[b.getOutputSize(plaintext.length)];
			int size1 = b.processBytes(plaintext, 0, plaintext.length, enc, 0);
			int size2;
			size2 = b.doFinal(enc, size1);
			byte[] ciphertext = new byte[size1 + size2];
			System.arraycopy(enc, 0, ciphertext, 0, ciphertext.length);
			return ciphertext;
		} catch (DataLengthException e) {
			e.printStackTrace();
			return null;
		} catch (IllegalStateException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] dec_AES(Mode mode, byte[] key, byte[] iv, byte[] ciphertext) {
		// Make sure the validity of key, and plaintext
		assert (key != null && ciphertext != null);
		// The valid key length is 16Bytes, 24Bytes or 32Bytes
		assert (key.length == 16 || key.length == 24 || key.length == 32);
		if (mode != Mode.ECB) {
			// The valid init vector is a no-none 16Bytes array
			assert (iv != null && iv.length == 16);
		}
		try {
			KeyParameter kp = new KeyParameter(key);
			BufferedBlockCipher b = null;
			switch (mode) {
			case ECB:
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(false, kp);
				break;
			case CBC:
				b = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
				b.init(false, new ParametersWithIV(kp, iv));
				break;
			case CFB:
				b = new PaddedBufferedBlockCipher(new CFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(false, new ParametersWithIV(kp, iv));
				break;
			case OFB:
				b = new PaddedBufferedBlockCipher(new OFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(false, new ParametersWithIV(kp, iv));
				break;
			default:
				// Default Mode is ECB Mode
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(false, kp);
				break;
			}
			byte[] dec = new byte[b.getOutputSize(ciphertext.length)];
			int size1 = b.processBytes(ciphertext, 0, ciphertext.length, dec, 0);
			int size2 = b.doFinal(dec, size1);
			byte[] plaintext = new byte[size1 + size2];
			System.arraycopy(dec, 0, plaintext, 0, plaintext.length);
			return plaintext;
		} catch (DataLengthException e) {
			e.printStackTrace();
			return null;
		} catch (IllegalStateException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void enc_AES(Mode mode, byte[] key, byte[] iv, InputStream in, OutputStream out) {
		// Make sure the validity of key, and plaintext
		assert (key != null && in != null && out != null);
		// The valid key length is 16Bytes, 24Bytes or 32Bytes
		assert (key.length == 16 || key.length == 24 || key.length == 32);
		if (mode != Mode.ECB) {
			// The valid init vector is a no-none 16Bytes array
			assert (iv != null && iv.length == 16);
		}
		try {
			KeyParameter kp = new KeyParameter(key);
			BufferedBlockCipher b = null;
			switch (mode) {
			case ECB:
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(true, kp);
				break;
			case CBC:
				b = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
				b.init(true, new ParametersWithIV(kp, iv));
				break;
			case CFB:
				b = new PaddedBufferedBlockCipher(new CFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(true, new ParametersWithIV(kp, iv));
				break;
			case OFB:
				b = new PaddedBufferedBlockCipher(new OFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(true, new ParametersWithIV(kp, iv));
				break;
			default:
				// Default Mode is ECB Mode
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(true, kp);
				break;
			}
			int inBlockSize = b.getBlockSize() * 10;
			int outBlockSize = b.getOutputSize(inBlockSize);
			byte[] inblock = new byte[inBlockSize];
			byte[] outblock = new byte[outBlockSize];

			int inL;
			int outL;
			byte[] rv = null;

			while ((inL = in.read(inblock, 0, inBlockSize)) > 0) {
				outL = b.processBytes(inblock, 0, inL, outblock, 0);

				if (outL > 0) {
					rv = Hex.encode(outblock, 0, outL);

					out.write(rv, 0, rv.length);
					out.write('\n');
				}
			}

			outL = b.doFinal(outblock, 0);
			if (outL > 0) {
				rv = Hex.encode(outblock, 0, outL);
				out.write(rv, 0, rv.length);
				out.write('\n');
			}
		} catch (DataLengthException e) {
			e.printStackTrace();
			return;
		} catch (IllegalStateException e) {
			e.printStackTrace();
			return;
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
			return;
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void dec_AES(Mode mode, byte[] key, byte[] iv, InputStream in, OutputStream out) {
		// Make sure the validity of key, and plaintext
		assert (key != null && in != null && out != null);
		// The valid key length is 16Bytes, 24Bytes or 32Bytes
		assert (key.length == 16 || key.length == 24 || key.length == 32);
		if (mode != Mode.ECB) {
			// The valid init vector is a no-none 16Bytes array
			assert (iv != null && iv.length == 16);
		}
		try {
			KeyParameter kp = new KeyParameter(key);
			BufferedBlockCipher b = null;
			switch (mode) {
			case ECB:
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(false, kp);
				break;
			case CBC:
				b = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
				b.init(false, new ParametersWithIV(kp, iv));
				break;
			case CFB:
				b = new PaddedBufferedBlockCipher(new CFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(false, new ParametersWithIV(kp, iv));
				break;
			case OFB:
				b = new PaddedBufferedBlockCipher(new OFBBlockCipher(new AESEngine(), DEFAULT_SIZE));
				b.init(false, new ParametersWithIV(kp, iv));
				break;
			default:
				// Default Mode is ECB Mode
				b = new PaddedBufferedBlockCipher(new AESEngine());
				b.init(false, kp);
				break;
			}
			BufferedReader br = new BufferedReader(new InputStreamReader(in));

			byte[] inblock = null;
			byte[] outblock = null;

			int outL;
			String rv = null;

			while ((rv = br.readLine()) != null) {
				inblock = Hex.decode(rv);
				outblock = new byte[b.getOutputSize(inblock.length)];

				outL = b.processBytes(inblock, 0, inblock.length, outblock, 0);
				if (outL > 0) {
					out.write(outblock, 0, outL);
				}
			}
			outL = b.doFinal(outblock, 0);
			if (outL > 0) {
				out.write(outblock, 0, outL);
			}
		} catch (DataLengthException e) {
			e.printStackTrace();
			return;
		} catch (IllegalStateException e) {
			e.printStackTrace();
			return;
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
			return;
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * @Description: TODO(AEC encrytion and decryption method realized through BouncyCastle)
	 * @param isEnc used for encryption or decryption
	 * @param mode work mode including ECB, CBC, CFB, OFB
	 * @param key symmetric key
	 * @param iv initial vector
	 * @param input plaintext or ciphertext
	 * @return 参数描述
	 * @throws
	 */
	public static byte[] enc_dec_AES_BC(Boolean isEnc, Mode mode, byte[] key, byte[] iv, byte[] input) {
		// Make sure the validity of key, and input
		assert (key != null && input != null);
		// The valid key length is 16Bytes, 24Bytes or 32Bytes
		assert (key.length == 16 || key.length == 24 || key.length == 32);
		if (mode != Mode.ECB) {
			// The valid init vector is a no-none 16Bytes array
			assert (iv != null && iv.length == 16);
		}
		try {
			String transformation = null;
			switch (mode) {
			case ECB:
				transformation = "AES/ECB/PKCS5Padding";
				break;
			case CBC:
				transformation = "AES/CBC/PKCS5Padding";
				break;
			case CFB:
				transformation = "AES/CFB/PKCS5Padding";
				break;
			case OFB:
				transformation = "AES/OFB/PKCS5Padding";
				break;
			default:
				// Default Mode is ECB Mode
				transformation = "AES/ECB/PKCS5Padding";
				break;
			}
			Cipher cipher = Cipher.getInstance(transformation);
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			IvParameterSpec ivps = null;
			if (null != iv) {
				ivps = new IvParameterSpec(iv);
			}
			if (isEnc) {
				cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivps);
			} else {
				cipher.init(Cipher.DECRYPT_MODE, keySpec, ivps);
			}
			return cipher.doFinal(input);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @Description: TODO(concatenate two byte array)
	 * @param bs1
	 * @param bs2
	 * @return 参数描述
	 * @throws
	 */
	public static byte[] concat(byte[] bs1, byte[] bs2) {
		byte[] r = new byte[bs1.length + bs2.length];
		System.arraycopy(bs1, 0, r, 0, bs1.length);
		System.arraycopy(bs2, 0, r, bs1.length, bs2.length);
		return r;
	}
}
