package cn.edu.ncepu.crypto.encryption.ecceg;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public class ECCEG {
	private ECCPoint publicKey;
	private BigInteger privateKey;
	private ECCPoint basePoint;
	private ECC ECC;

	public ECCEG(ECC ECC, ECCPoint basePoint) {
		this.ECC = ECC;
		this.basePoint = basePoint;
		this.privateKey = new BigInteger(ECC.p.bitLength(), new Random()).mod(ECC.p.subtract(BigInteger.ONE))
				.add(BigInteger.ONE);
		this.publicKey = ECC.multiply(privateKey, basePoint);
	}

	public ECCEG(ECC ECC, ECCPoint basePoint, BigInteger privateKey) {
		this.ECC = ECC;
		this.basePoint = basePoint;
		this.privateKey = privateKey;
		this.publicKey = ECC.multiply(privateKey, basePoint);
	}

	public ECCPoint getPublicKey() {
		return this.publicKey;
	}

	public BigInteger getPrivateKey() {
		return this.privateKey;
	}

	public ECC getECC() {
		return this.ECC;
	}

	public ECCPoint getBasePoint() {
		return this.basePoint;
	}

	public void setPublicKey(ECCPoint publicKey) {
		this.publicKey = publicKey;
	}

	public void setPrivateKey(BigInteger privateKey) {
		this.privateKey = privateKey;
	}

	public boolean savePublicKey(String fileName) {
		try {
			File file = new File(fileName);
			if (!file.exists())
				file.createNewFile();
			FileOutputStream fop = new FileOutputStream(file);
			fop.write(publicKey.x.toString().getBytes());
			fop.write(' ');
			fop.write(publicKey.y.toString().getBytes());
			fop.flush();
			fop.close();
			return true;
		} catch (IOException e) {
		}
		return false;
	}

	public boolean savePrivateKey(String fileName) {
		try {
			File file = new File(fileName);
			if (!file.exists())
				file.createNewFile();
			FileOutputStream fop = new FileOutputStream(file);
			fop.write(privateKey.toString().getBytes());
			fop.flush();
			fop.close();
			return true;
		} catch (IOException e) {
		}
		return false;
	}

	public boolean loadPublicKey(String fileName) {
		try {
			File file = new File(fileName);
			Scanner sc = new Scanner(file);
			BigInteger x = null, y = null;
			if (sc.hasNextBigInteger())
				x = sc.nextBigInteger();
			if (sc.hasNextBigInteger())
				y = sc.nextBigInteger();
			sc.close();
			if (x != null && y != null) {
				this.publicKey = new ECCPoint(x, y);
				return true;
			}
		} catch (IOException e) {
		}
		return false;
	}

	public boolean loadPrivateKey(String fileName) {
		try {
			File file = new File(fileName);
			Scanner sc = new Scanner(file);
			BigInteger i = null;
			if (sc.hasNextBigInteger())
				i = sc.nextBigInteger();
			sc.close();
			if (i != null) {
				this.privateKey = i;
				return true;
			}
		} catch (IOException e) {
		}
		return false;
	}

	public Pair<ECCPoint, ECCPoint> encrypt(ECCPoint p) {
		BigInteger k = new BigInteger(ECC.p.bitLength(), new Random()).mod(ECC.p.subtract(BigInteger.ONE))
				.add(BigInteger.ONE);
		ECCPoint left = ECC.multiply(k, basePoint);
		ECCPoint right = ECC.add(p, ECC.multiply(k, publicKey));
		return new Pair<ECCPoint, ECCPoint>(left, right);
	}

	public List<Pair<ECCPoint, ECCPoint>> encryptBytes(byte[] bytes) {
		List<Pair<ECCPoint, ECCPoint>> ret = new ArrayList<>();
		for (int i = 0; i < bytes.length; ++i)
			ret.add(encrypt(ECC.intToPoint(BigInteger.valueOf(bytes[i]))));
		return ret;
	}

	public ECCPoint decrypt(Pair<ECCPoint, ECCPoint> p) {
		ECCPoint m = ECC.multiply(privateKey, p.left);
		return ECC.subtract(p.right, m);
	}

	public List<ECCPoint> decrypt(List<Pair<ECCPoint, ECCPoint>> l) {
		List<ECCPoint> ret = new ArrayList<>();
		for (Pair<ECCPoint, ECCPoint> p : l)
			ret.add(decrypt(p));
		return ret;
	}
}
