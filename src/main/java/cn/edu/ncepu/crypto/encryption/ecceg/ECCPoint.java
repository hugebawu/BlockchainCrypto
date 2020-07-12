package cn.edu.ncepu.crypto.encryption.ecceg;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Point;

public class ECCPoint implements Point<Element> {
	public BigInteger x, y;
	public boolean infinite;

	public ECCPoint() {
		x = y = BigInteger.ZERO;
		infinite = false;
	}

	public ECCPoint(boolean infinite) {
		x = y = BigInteger.ZERO;
		this.infinite = infinite;
	}

	public ECCPoint(BigInteger x, BigInteger y) {
		this.x = x;
		this.y = y;
	}

	public String toString() {
		return "(" + x + ", " + y + ")";
	}

	@Override
	public Field getField() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getLengthInBytes() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean isImmutable() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Element getImmutable() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element duplicate() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element set(Element value) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element set(int value) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element set(BigInteger value) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger toBigInteger() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element setToRandom() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element setFromHash(byte[] source, int offset, int length) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int setFromBytes(byte[] source) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int setFromBytes(byte[] source, int offset) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public byte[] toBytes() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] toCanonicalRepresentation() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element setToZero() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isZero() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Element setToOne() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isEqual(Element value) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isOne() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Element twice() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element square() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element invert() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element halve() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element negate() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element add(Element element) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element sub(Element element) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element mul(Element element) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element mul(int z) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element mul(BigInteger n) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element mulZn(Element z) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element div(Element element) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element pow(BigInteger n) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element powZn(Element n) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ElementPowPreProcessing getElementPowPreProcessing() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element sqrt() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isSqr() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int sign() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int getSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Element getAt(int index) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element getX() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element getY() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getLengthInBytesCompressed() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public byte[] toBytesCompressed() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int setFromBytesCompressed(byte[] source) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int setFromBytesCompressed(byte[] source, int offset) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int getLengthInBytesX() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public byte[] toBytesX() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int setFromBytesX(byte[] source) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int setFromBytesX(byte[] source, int offset) {
		// TODO Auto-generated method stub
		return 0;
	}
}
