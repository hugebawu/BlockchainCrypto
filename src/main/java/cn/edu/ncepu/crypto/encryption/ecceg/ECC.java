package cn.edu.ncepu.crypto.encryption.ecceg;

import java.math.BigInteger;

public class ECC {
	public final BigInteger a, b, p;
	private BigInteger k = BigInteger.valueOf(20);
	private static BigInteger MINUS_ONE = BigInteger.valueOf(-1), ZERO = BigInteger.valueOf(0),
			ONE = BigInteger.valueOf(1), TWO = BigInteger.valueOf(2), THREE = BigInteger.valueOf(3);

	public ECC(BigInteger a, BigInteger b, BigInteger p) {
		this.a = a;
		this.b = b;
		this.p = p;
	}

	public ECCPoint add(ECCPoint p, ECCPoint q) {
		if (p.x.compareTo(q.x) == 0 && p.y.compareTo(q.y) == 0)
			return doubles(p);
		else if (p.infinite && q.infinite)
			return new ECCPoint(true);
		else if (p.infinite)
			return q;
		else if (q.infinite)
			return p;
		else if (p.x.compareTo(q.x) == 0)
			return new ECCPoint(true);

		BigInteger gradient = q.y.subtract(p.y).multiply(q.x.subtract(p.x).mod(this.p).modInverse(this.p)).mod(this.p);
		BigInteger x = gradient.multiply(gradient).subtract(p.x).subtract(q.x).mod(this.p);
		BigInteger y = gradient.multiply(p.x.subtract(x)).subtract(p.y).add(this.p).mod(this.p);
		return new ECCPoint(x, y);
	}

	public ECCPoint subtract(ECCPoint p, ECCPoint q) {
		ECCPoint minusQ = new ECCPoint(q.x, q.y.negate().mod(this.p));
		return add(p, minusQ);
	}

	public ECCPoint doubles(ECCPoint a) {
		BigInteger gradient = a.x.multiply(a.x).multiply(THREE).add(this.a)
				.multiply(a.y.multiply(TWO).modInverse(this.p)).mod(this.p);
		BigInteger x = gradient.multiply(gradient).subtract(a.x.multiply(TWO)).mod(this.p);
		BigInteger y = gradient.multiply(a.x.subtract(x)).subtract(a.y).mod(this.p);
		return new ECCPoint(x, y);
	}

	public ECCPoint multiply(BigInteger n, ECCPoint p) {
		if (n.equals(ZERO))
			return new ECCPoint(ZERO, ZERO);
		else if (n.equals(ONE))
			return p;
		else if (n.mod(TWO).equals(ZERO))
			return multiply(n.divide(TWO), doubles(p));
		else
			return add(multiply(n.subtract(ONE), p), p);
	}

	public BigInteger solveY(BigInteger x) {
		BigInteger y2 = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
		return SquareRootModulo.sqrtP(y2, p);
	}

	public ECCPoint intToPoint(BigInteger m) {
		BigInteger mk = m.multiply(k);
		for (BigInteger i = ONE; i.compareTo(k) < 0; i = i.add(ONE)) {
			BigInteger x = mk.add(i);
			BigInteger y = solveY(x);
			if (y != null)
				return new ECCPoint(x.mod(p), y.mod(p));
		}
		return new ECCPoint(BigInteger.valueOf(-1), BigInteger.valueOf(-1));
	}

	public BigInteger pointToInt(ECCPoint p) {
		return p.x.subtract(ONE).divide(this.k);
	}

	public ECCPoint getBasePoint() {
		for (BigInteger x = ZERO; x.compareTo(this.p) < 0; x = x.add(ONE)) {
			BigInteger y = solveY(x);
			if (y != null)
				return new ECCPoint(x, y);
		}
		return null;
	}

	// Helper class for square root mod
	private static class SquareRootModulo {
		public static BigInteger sqrtP(BigInteger x, BigInteger p) {
			if (p.mod(TWO).equals(ZERO))
				return null;
			BigInteger q = p.subtract(ONE).divide(TWO);
			if (!x.modPow(q, p).equals(ONE))
				return null;

			while (q.mod(TWO).equals(ZERO)) {
				q = q.divide(TWO);
				if (!x.modPow(q, p).equals(ONE))
					return complexSqrtP(x, q, p);
			}
			q = q.add(ONE).divide(TWO);
			return x.modPow(q, p);
		}

		private static BigInteger complexSqrtP(BigInteger x, BigInteger q, BigInteger p) {
			BigInteger a = findNonResidue(p);
			if (a == null)
				return null;
			BigInteger t = p.subtract(ONE).divide(TWO);
			BigInteger negativePower = t;

			while (q.mod(TWO).equals(ZERO)) {
				q = q.divide(TWO);
				t = t.divide(TWO);
				if (x.modPow(q, p).compareTo(a.modPow(t, p)) != 0)
					t = t.add(negativePower);
			}
			BigInteger inverse = x.modInverse(p);
			BigInteger partOne = inverse.modPow(q.subtract(ONE).divide(TWO), p);
			BigInteger partTwo = a.modPow(t.divide(TWO), p);
			return partOne.multiply(partTwo).mod(p);
		}

		private static BigInteger findNonResidue(BigInteger p) {
			BigInteger a = BigInteger.valueOf(2);
			BigInteger q = p.subtract(ONE).divide(TWO);
			while (true) {
				if (a.modPow(q, p).equals(ONE))
					return a;
				a = a.add(ONE);
				if (a.compareTo(p) >= 0)
					return null;
			}
		}
	}
}
