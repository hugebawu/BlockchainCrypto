package cn.edu.ncepu.crypto.utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Utilities for pairing-based cryptography.
 */
@SuppressWarnings("rawtypes")
public class PairingUtils {
	public static final String PATH_a_160_512 = "params/a_160_512.properties";
	public static final String PATH_a_256_1024 = "params/a_256_1024.properties";
	//    public static final String PATH_a_320_512 = "params/a_320_512.properties";
	public static final String PATH_a1_2_256 = "params/a1_2_256.properties";
	public static final String PATH_a1_3_128 = "params/a1_3_128.properties";
	//    public static final String PATH_a1_3_256 = "params/a1_3_256.properties";
//    public static final String PATH_a1_2_512 = "params/a1_2_512.properties";
	public static final String PATH_a1_3_512 = "params/a1_3_512.properties";
	public static final String PATH_f_160 = "params/f_160.properties";
	public static final String PATH_f_256 = "params/f_256.properties";
	public static final String PATH_f_512 = "params/f_512.properties";
	public static final String PATH_a = "params/a.properties";

	public static final String TEST_PAIRING_PARAMETERS_PATH_a_80_256 = "params/a_80_256.properties";
	public static final String TEST_PAIRING_PARAMETERS_PATH_a1_2_128 = "params/a1_2_128.properties";
	public static final String TEST_PAIRING_PARAMETERS_PATH_a1_3_128 = "params/a1_3_128.properties";

	public static final int DEFAULT_SIMU_TEST_ROUND = 2;
	public static final int DEFAULT_PRIME_ORDER_TEST_ROUND = 100;
	public static final int DEFAULT_COMPOSITE_ORDER_TEST_ROUND = 20;

	public enum PairingGroupType {
		Zr, G1, G2, GT,
	}

	/**
	 * Generate type A pairing parameter in pairing-based cryptography.
	 * Zr={0,...,r-1}; G is the Elliptic curve defied in the field Fq whose order is r.
	 * GT is defined in Fq2; h*r = q+1
	 * @param rbits bit length for the r
	 * @param qbits bit length for the q
	 * @return Type A pairing parameters
	 */
	public static PropertiesParameters genTypeAPairParam(int rbits, int qbits) {
		TypeACurveGenerator pairParamGenerator = new TypeACurveGenerator(rbits, qbits);
		return (PropertiesParameters) pairParamGenerator.generate();
	}

	/**
	 * Generate type A pairing parameter in pairing-based cryptography.
	 * r is given and cannot be chosen; p + 1 = n*l;
	 * p is prime ,same as the q in type A; n is the order of the group
	 * @param numPrime: the number of prime factors in n
	 * @param bits: bit length for each prime factor
	 * @return Type A1 pairing parameters
	 */
	public static PropertiesParameters genTypeA1PairParam(int numPrime, int bits) {
		TypeA1CurveGenerator pairParamGenerator = new TypeA1CurveGenerator(numPrime, bits);
		return (PropertiesParameters) pairParamGenerator.generate();
	}

	/**
	 * @description: type F pairing parameter in pairing-based cryptography.
	 * @param qbits the curve is defined over Fq
	 * @param: rbits the order of ther curve
	 * @return: b E: y^2=x^3 + b
	 * @throw:
	 */
	public static PropertiesParameters genTypeFPairParam(int rbits) {
		TypeFCurveGenerator pairParamGenerator = new TypeFCurveGenerator(rbits);
		return (PropertiesParameters) pairParamGenerator.generate();
	}

	/**
	 *   这里描述这个方法的作用 参数描述
	 */
	@Deprecated
	public static Element xor(Pairing pairing, byte[] arrayM, byte[] arrayGTElement) {
		byte[] arrayGTElement1 = Arrays.copyOfRange(arrayGTElement, 0, arrayGTElement.length / 2);
		byte[] arrayGTElement2 = Arrays.copyOfRange(arrayGTElement, arrayGTElement.length / 2, arrayGTElement.length);
		byte[] array1 = CommonUtils.xor(arrayM, arrayGTElement1);
		byte[] array2 = CommonUtils.xor(arrayM, arrayGTElement2);
		byte[] result = new byte[array1.length + array2.length];
		System.arraycopy(array1, 0, result, 0, array1.length);
		System.arraycopy(array2, 0, result, array1.length, array2.length);
		return pairing.getGT().newElementFromBytes(result).getImmutable();
	}

	/**
	 *   这里描述这个方法的作用 参数描述
	 */
	@Deprecated
	public static Element xor(Pairing pairing, Element e1, Element e2) {
		byte[] results = CommonUtils.xor(e1.toBytes(), e2.toBytes());
		return pairing.getGT().newElementFromBytes(results).getImmutable();
	}

	/**
	 *   concate x,y into GTElement
	 * @param GTEArrayLeft
	 * @param GTEArrayRight
	 * @param GTEBytelength
	 * @return 
	 */
	@Deprecated
	public static byte[] concate(byte[] GTEArrayLeft, byte[] GTEArrayRight, int GTEBytelength) {
		byte[] result = new byte[GTEBytelength];
		int aLen = GTEArrayLeft.length;
		int bLen = GTEArrayRight.length;
		int i = aLen - 1, j = bLen - 1;
		for (int k = result.length / 2 - 1; i >= 0; i--, k--) {
			result[k] = GTEArrayLeft[i];
		}
		for (int k = result.length - 1; j >= 0; j--, k--) {
			result[k] = GTEArrayRight[j];
		}
		return result;
	}

	/**
	 *   add two GT element
	 * @param pairing
	 * @param order the order of GT element x,y value
	 * @param e1
	 * @param e2
	 * @return 
	 */
	@Deprecated
	public static Element add(Pairing pairing, BigInteger order, Element e1, Element e2) {
		byte[] e1Left = Arrays.copyOfRange(e1.toBytes(), 0, e1.getLengthInBytes() / 2);
		byte[] e1Right = Arrays.copyOfRange(e1.toBytes(), e1.getLengthInBytes() / 2, e1.getLengthInBytes());

		byte[] e2Left = Arrays.copyOfRange(e2.toBytes(), 0, e2.getLengthInBytes() / 2);
		byte[] e2Right = Arrays.copyOfRange(e2.toBytes(), e2.getLengthInBytes() / 2, e2.getLengthInBytes());

		BigInteger temp = new BigInteger(e1Left).add(new BigInteger(e2Left));
		BigInteger temp2 = temp.add(order).mod(order);
		byte[] resultLeft = temp2.toByteArray();
		byte[] resultRight = (new BigInteger(e1Right).add(new BigInteger(e2Right))).mod(order).toByteArray();

		byte[] results = concate(resultLeft, resultRight, e1.getLengthInBytes());
		return pairing.getGT().newElementFromBytes(results).getImmutable();
	}

	/**
	 * the hash function G described in Boneh-Franklin CPA-secure IBE
	 * G: {0,1}*->Fp, hash user id to a point in the G1
	 *
	 * @param Pairing
	 * @param ID      user id
	 * @return 参数描述
	 */
	public static Element hash_G(Pairing Pairing, String ID) {
		byte[] shaResult = CommonUtils.hash(ID.getBytes(), "SHA256");
		return Pairing.getG1().newElementFromHash(shaResult, 0, shaResult.length).getImmutable();
	}

	/**
	 *   the hash function H described in Boneh-Franklin CPA-secure IBE
	 * @param pairing
	 * @param element element in GT
	 * @return a element in GT
	 */
	public static Element hash_H(Pairing pairing, Element element) {
		byte[] bytes = element.toBytes();
		return pairing.getGT().newElementFromHash(bytes, 0, bytes.length).getImmutable();
	}

//	public CurveElement mapString2CurveElement(String numString) {
//		CurveElement M = (CurveElement) curveField.newElement();
//		M.setFromBytesX(new BigInteger(numString).toByteArray());
//		return (CurveElement) M.getImmutable();
//	}
//
//	public String mapCurveElement2String(CurveElement element) {
//		ZrElement M = (ZrElement) element.getX();
//		return M.toBigInteger().toString();
//	}

	/**
	 *   map the decimal String(e.g,"123456789012345678901234567890" into a element in the pairingGroup)
	 * Attention: when pairingGroupType = Zr, numString need to be smaller than r; 
	 * when pairingGroupType = GT, numString need to be smaller than q
	 * @param pairing
	 * @param numString
	 * @param pairingGroupType
	 * @return 
	 */
	public static Element mapNumStringToElement(Pairing pairing, String numString, PairingGroupType pairingGroupType) {
		BigInteger biNum = new BigInteger(numString);
		BigInteger order = null;
		switch (pairingGroupType) {
		case Zr:
			order = pairing.getZr().getOrder();
			if (1 == biNum.compareTo(order)) {
				throw new IllegalArgumentException("numString should less than " + order);
			}
			return pairing.getZr().newElement(biNum).getImmutable();
		case G1:
//			order = (BigInteger) (pairing.getG1().newElement().getField().getOrder());
//			if (1 == biNum.compareTo(order)) {
//				throw new IllegalArgumentException("numString should less than " + order);
//			}
			CurveElement M = (CurveElement) pairing.getG1().newElement();
			M.setFromBytesX(new BigInteger(numString).toByteArray());
			return M.getImmutable();
		case GT:
			order = pairing.getGT().getOrder();
			if (1 == biNum.compareTo(order)) {
				throw new IllegalArgumentException("numString should less than " + order);
			}
			return pairing.getGT().newElement(biNum).getImmutable();
		default:
			throw new RuntimeException("Invalid pairing group type.");
		}
	}

	/**
	 *   map a element in the pairingGroup into the decimal string(e.g,"123456789012345678901234567890")
	 * @param e GT element
	 * @return 参数描述
	 */
	public static String mapElementToNumString(Element e, PairingGroupType pairingGroupType) {
		switch (pairingGroupType) {
		case Zr:
		case G1:
			return ((CurveElement) e).getX().toBigInteger().toString();
		case GT:
			return e.toBigInteger().toString(10);
		default:
			throw new RuntimeException("Invalid pairing group type.");
		}
	}

	public static Element MapByteArrayToGroup(Pairing pairing, byte[] message, PairingGroupType pairingGroupType) {
		byte[] shaResult = CommonUtils.hash(message, "SHA256");
		switch (pairingGroupType) {
		case Zr:
			return pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
		case G1:
			return pairing.getG1().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
		case G2:
			return pairing.getG2().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
		case GT:
			return pairing.getGT().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
		default:
			throw new RuntimeException("Invalid pairing group type.");
		}
	}

	public static Element MapStringToGroup(Pairing pairing, String message, PairingGroupType pairingGroupType) {
		return PairingUtils.MapByteArrayToGroup(pairing, message.getBytes(), pairingGroupType);
	}

	public static Element MapByteArrayToFirstHalfZr(Pairing pairing, byte[] message) {
		byte[] shaResult = CommonUtils.hash(message, "SHA256");
		byte[] hashZr = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).toBytes();
		hashZr[0] &= 0xEF;
		return pairing.getZr().newElementFromBytes(hashZr).getImmutable();
	}

	public static Element MapByteArrayToSecondHalfZr(Pairing pairing, byte[] message) {
		byte[] shaResult = CommonUtils.hash(message, "SHA256");
		byte[] hash = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).toBytes();
		hash[0] |= 0x80;
		return pairing.getZr().newElementFromBytes(hash).getImmutable();
	}

	public static Element[] MapStringArrayToGroup(Pairing pairing, String[] message,
			PairingGroupType pairingGroupType) {
		Element[] elements = new Element[message.length];
		for (int i = 0; i < elements.length; i++) {
			if (message[i] == null) {
				continue;
			}
			elements[i] = PairingUtils.MapByteArrayToGroup(pairing, message[i].getBytes(), pairingGroupType);
		}
		return elements;
	}

	public static Element[] MapStringArrayToFirstHalfZr(Pairing pairing, String[] message) {
		Element[] elements = new Element[message.length];
		for (int i = 0; i < elements.length; i++) {
			elements[i] = PairingUtils.MapByteArrayToFirstHalfZr(pairing, message[i].getBytes());
		}
		return elements;
	}

	public static String[] MapElementArrayToStringArray(Element[] message) {
		String[] strings = new String[message.length];
		for (int i = 0; i < message.length; i++) {
			strings[i] = message[i].toString();
		}
		return strings;
	}

	public static boolean isEqualElement(final Element thisElement, final Element thatElement) {
		if (thisElement == null && thatElement != null) {
			return false;
		}
		if (thisElement != null && thatElement == null) {
			return false;
		}
		if (thisElement == thatElement) {
			return true;
		}
		String stringThisElement = new String(Hex.encode(thisElement.toBytes()));
		String stringThatElement = new String(Hex.encode(thatElement.toBytes()));
		return (stringThisElement.equals(stringThatElement));
	}

	public static boolean isEqualElementArray(final Element[] thisElementArray, final Element[] thatElementArray) {
		if (thisElementArray == thatElementArray) {
			return true;
		}
		if (thisElementArray.length != thatElementArray.length) {
			return false;
		}
		for (int i = 0; i < thisElementArray.length; i++) {
			if (!(PairingUtils.isEqualElement(thisElementArray[i], thatElementArray[i]))) {
				return false;
			}
		}
		return true;
	}

	public static boolean isEqualByteArrays(final byte[][] thisByteArrays, final byte[][] thatByteArrays) {
		if (thisByteArrays == thatByteArrays) {
			return true;
		}
		if (thisByteArrays.length != thatByteArrays.length) {
			return false;
		}
		for (int i = 0; i < thisByteArrays.length; i++) {
			if (!(Arrays.equals(thisByteArrays[i], thatByteArrays[i]))) {
				return false;
			}
		}
		return true;
	}

	public static boolean isEqualByteArrayMaps(final Map<String, byte[]> thisMap, final Map<String, byte[]> thatMap) {
		if (thisMap == thatMap) {
			return true;
		}
		for (String thisString : thisMap.keySet()) {
			if (!Arrays.equals(thisMap.get(thisString), thatMap.get(thisString))) {
				return false;
			}
		}
		for (String thatString : thatMap.keySet()) {
			if (!Arrays.equals(thisMap.get(thatString), thatMap.get(thatString))) {
				return false;
			}
		}
		return true;
	}

	public static byte[][] GetElementArrayBytes(Element[] elementArray) {
		byte[][] byteArrays = new byte[elementArray.length][];
		for (int i = 0; i < byteArrays.length; i++) {
			if (elementArray[i] == null) {
				byteArrays[i] = null;
				continue;
			}
			byteArrays[i] = elementArray[i].toBytes();
		}
		return byteArrays;
	}

	public static Element[] GetElementArrayFromBytes(Pairing pairing, byte[][] byteArrays, PairingGroupType groupType) {
		Element[] elementArray = new Element[byteArrays.length];
		for (int i = 0; i < elementArray.length; i++) {
			if (byteArrays[i] == null) {
				elementArray[i] = null;
				continue;
			}
			switch (groupType) {
			case Zr:
				elementArray[i] = pairing.getZr().newElementFromBytes(byteArrays[i]).getImmutable();
				break;
			case G1:
				elementArray[i] = pairing.getG1().newElementFromBytes(byteArrays[i]).getImmutable();
				break;
			case G2:
				elementArray[i] = pairing.getG2().newElementFromBytes(byteArrays[i]).getImmutable();
				break;
			case GT:
				elementArray[i] = pairing.getGT().newElementFromBytes(byteArrays[i]).getImmutable();
				break;
			default:
				throw new RuntimeException("Invalid pairing group type.");
			}
		}
		return elementArray;
	}

	public static String[] removeDuplicates(String[] orginalArray) {
		Set<String> stringSet = new HashSet<String>();
		Collections.addAll(stringSet, orginalArray);
		return stringSet.toArray(new String[1]);
	}

	public static int[] removeDuplicates(int[] originalArray) {
		Set<Integer> intSet = new HashSet<Integer>();
		for (int i : originalArray) {
			intSet.add(i);
		}
		int[] resultSet = new int[intSet.size()];
		int label = 0;
		for (Integer setInteger : intSet) {
			resultSet[label] = setInteger;
			label++;
		}
		return resultSet;
	}

	public static void NotVerifyCipherParameterInstance(String schemeName, Object parameters, String className) {
		throw new IllegalArgumentException("Invalid CipherParameter Instance of " + schemeName + ", find "
				+ parameters.getClass().getName() + ", require" + className);
	}
}
