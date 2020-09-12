/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.eccegHE;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.algebra.Engine;
import cn.edu.ncepu.crypto.homomorphicEncryption.CipherText;
import cn.edu.ncepu.crypto.homomorphicEncryption.HE;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.curve.ImmutableCurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ImmutableZrElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeAPairing;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 12, 2020 2:11:08 PM
 * @ClassName ECElgamalHEEngine
 * @Description:  (elliptic curve based elgamal cryptosystem which has the characteristic of homomorphism)
 * 虽然没验证成功，但是通过文献看出来是乘法同态。
 */
public class ECElgamalHEEngine extends Engine implements HE {
	private static Logger logger = LoggerFactory.getLogger(ECElgamalHEEngine.class);
	// Scheme name, used for exceptions
	private static final String SCHEME_NAME = "elleptic curve based elgamal encryption based homomorphic encryption scheme";
	private static ECElgamalHEEngine engine;
	// system parameters: params = <p,q,n,P,G>
	private Element P; // G1的生成元
	private Element Q; // 用户公钥
	private TypeAPairing pairing;
	// G1是定义在域Fq上的椭圆曲线，其阶为r.q与r都是质数，且存在一定的关系：这里是 (q+1)=r*h
	// Zr 是阶为r的环Zr={0,...,r-1}
	private ZrField Zr;
	private CurveField<ZrField> G1;

	public static ECElgamalHEEngine getInstance(Pairing pairing) {
		if (null == engine) {
			engine = new ECElgamalHEEngine(pairing);
		}
		return engine;
	}

	@SuppressWarnings("unchecked")
	public ECElgamalHEEngine(Pairing pairing) {
		super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.ANON);
		this.pairing = (TypeAPairing) pairing;
		// 将变量r初始化为Zr中的元素
		Zr = (ZrField) pairing.getZr();
		// 将变量Ppub，Qu，Su，V初始化为G1中的元素，G1是加法群
		G1 = (CurveField<ZrField>) pairing.getG1();

	}

	@Override
	public void setup() {
		P = G1.newRandomElement().getImmutable();// 生成G1的生成元P
		logger.info("P=" + P);
	}

	@Override
	public Element keyGen(String id) {
		// 用户随即生成私钥, 并发布公钥
		Element d = Zr.newRandomElement().getImmutable();
		// Q = dP
		Q = P.mulZn(d);
		return d;
	}

	@SuppressWarnings("unchecked")
	@Override
	// 注意，这里M不能过长，受到Fq2中q的大小限制
	public ECElgamalHECipherText encrypt(String message) {
		// 通过Hash函数G将密文映射到E上 M = hash_G(m)
		Element M = PairingUtils.mapNumStringToElement(pairing, message, PairingGroupType.G1);
		logger.info("original_M:" + M);
		Element r = Zr.newRandomElement().getImmutable();
		// 密文的第一部分 U = rP
		ImmutableCurveElement<ImmutableZrElement, CurveField<ZrField>> U = (ImmutableCurveElement<ImmutableZrElement, CurveField<ZrField>>) P
				.mulZn(r).getImmutable();
		// 密文的第二部分 V = M + rQ; M 是明文. 密文: C = (U, V)
		// -------------------------------------------------------------------------------
		// 验证G1中的元素(x,y)满足 y^2 mod (q) = (x^3+x) mod (q)
		BigInteger x = ((ImmutableZrElement) U.getX()).toBigInteger();
		BigInteger y = ((ImmutableZrElement) U.getY()).toBigInteger();
		BigInteger q = pairing.getQ();
		BigInteger left = y.modPow(new BigInteger("2"), q);
		BigInteger right = (x.modPow(new BigInteger("3"), q).add(x)).mod(q);
		assertTrue(left.equals(right));
		// ----------------------------------------------------------------------------------------------------------------
		Element rQ = Q.mulZn(r).getImmutable();
		logger.info(" rQ:" + rQ);
		Element V = M.mul(rQ).getImmutable();
		logger.info(" V :" + V);
		return new ECElgamalHECipherText(U, V, r, P, Q);
	}

	@Override
	public String decrypt(Element d, CipherText ciphertext) {
		// 因为 dU=drP=rdP=rQ, 所以明文: M = V - dU
		Element U = ciphertext.getU();
		Element V = ciphertext.getV();
		Element dU = U.mulZn(d).getImmutable();
		logger.info("dU:" + dU);
		Element decrypte_M = V.div(dU).getImmutable();
		logger.info("decrypte_M:" + decrypte_M);
		return PairingUtils.mapElementToNumString(decrypte_M, PairingGroupType.G1);
	}

	@Override
	public CipherText eval(Map<String, CipherText> ciphertextMap) {
		Element U = this.G1.newZeroElement();
		Element V = this.G1.newZeroElement();
		Element r = this.Zr.newZeroElement();
		Element P = this.G1.newZeroElement();
		Element Q = this.G1.newZeroElement();
		for (CipherText ciphertext : ciphertextMap.values()) {
			ECElgamalHECipherText ecElgamalCiphertext = (ECElgamalHECipherText) ciphertext;
			U = U.add(ecElgamalCiphertext.getU());
			V = V.add(ecElgamalCiphertext.getV());
			r = r.add(ecElgamalCiphertext.getR());
			Element temp_P = ecElgamalCiphertext.getP();
			if (P.isZero()) {
				P = temp_P;
			} else {
				assertTrue(P.isEqual(temp_P));
			}
			Q = Q.add(ecElgamalCiphertext.getQ());
		}
		return new ECElgamalHECipherText(U.getImmutable(), V.getImmutable(), r.getImmutable(), P.getImmutable(),
				Q.getImmutable());
	}

}
