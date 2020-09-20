/**
 * 
 */
package cn.edu.ncepu.crypto.homomorphicEncryption.basicIBEHE;

import cn.edu.ncepu.crypto.homomorphicEncryption.CipherText;
import cn.edu.ncepu.crypto.homomorphicEncryption.HE;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import it.unisa.dia.gas.plaf.jpbc.field.quadratic.DegreeTwoExtensionQuadraticField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeAPairing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 *
 * @版权 : Copyright (c) 2018-2019 E1101智能电网信息安全中心
 * @author: Hu Baiji
 * @E-mail: drbjhu@163.com
 * @创建日期: 2019年10月16日 下午7:37:14
 * @ClassName BasicIdent2
 * @类描述-Description: basec ibe based homomorphic encryption
 * 系统建立buildSystem()，密钥提取extractSecretKey()，加密encrypt()，解密decrypt()。
 * BasicIdent的基于身份的加密体制是由Boneh和Franklin在《Identity-Based Encryption fromthe Weil Pairing》提出的
 * @修改记录:
 * @版本: 1.0
 */

public class BasicIBEHEEngine implements HE {
	private static final Logger logger = LoggerFactory.getLogger(BasicIBEHEEngine.class);
	// system parameters: params = <q,n,P,Ppub,G,H>
	private Element s, // master key
			P, // G1的生成元
			Ppub, // Ppub = sP
			Qu; // 用户公钥 Qu = hash_G("User ID")
	private final TypeAPairing pairing;
	// G1是定义在域Fq上的椭圆曲线，其阶为r.q与r都是质数，且存在一定的关系：这里是 (q+1)=r*h
	// Zr 是阶为r的环Zr={0,...,r-1}
	// GT是有限域Fq2。其元素的阶虽然为r，但是其取值范围比q大的多，目前不清楚怎么回事。
	private final ZrField Zr;
	private final CurveField<ZrField> G1;
	private final GTFiniteField<DegreeTwoExtensionQuadraticField<ZrField>> GT;

	@SuppressWarnings("unchecked")
	public BasicIBEHEEngine(PairingParameters typeAParams) {
		this.pairing = (TypeAPairing) PairingFactory.getPairing(typeAParams);
		// For bilinear maps only, to use the PBC wrapper and gain in performance, the
		// usePBCWhenPossible property of the pairing factory must be set.
		// Moreover, if PBC and the JPBC wrapper are not installed properly then the
		// factory will resort to the JPBC pairing implementation.
		// 需要配置才能使用http://gas.dia.unisa.it/projects/jpbc/docs/pbcwrapper.html#.XvnxeygzZPY
		PairingFactory.getInstance().setUsePBCWhenPossible(true);//
		// 判断配对是否为对称配对，不对称则输出错误信息
		if (!pairing.isSymmetric()) {
			throw new RuntimeException("密钥不对称!");
		}
		// 将变量r初始化为Zr中的元素
		Zr = (ZrField) pairing.getZr();
		// 将变量Ppub，Qu，Su，V初始化为G1中的元素，G1是加法群
		G1 = (CurveField<ZrField>) pairing.getG1();
		// 将变量T1，T2V初始化为GT中的元素，GT是乘法群
		GT = (GTFiniteField<DegreeTwoExtensionQuadraticField<ZrField>>) pairing.getGT();

		// Create a new element with a specified value
		logger.info("Zr order: " + Zr.getOrder());
		logger.info("Zr order bits length: " + Zr.getOrder().bitLength());
		Element elementZr1 = Zr.newElement(new BigInteger("539084384990328"));
		Element elementZr2 = Zr.newElement(4);
		logger.info("elementZr2 invert: " + elementZr2.invert().toString());
		logger.info("elementZr2 is quadratic residue?: " + elementZr2.isSqr());
		logger.info("" + elementZr1.sign());
		logger.info("");
		logger.info("G1 order: " + G1.getOrder());
		logger.info("G1 order bits length: " + G1.getOrder().bitLength());
		logger.info("");
		logger.info("GT order: " + GT.getOrder());
		logger.info("GT order bits length: " + GT.getOrder().bitLength());
		logger.info("GT bits length: " + GT.getLengthInBytes() * 8);
		logger.info("");
		// 方案1
		// 当PairingGroupType = Zr, bigNum需要小于r
		// 当PairingGroupType = GT, bigNum需要小于q
		String bigNum = "604462909877683331530750";
		// 604462909877683331530750
		// 81869981414486565817042987620009425916711137248094272342132238763687306328558
		logger.info(" original bigNum: " + bigNum);
		logger.info("bigNum bit lengh: " + new BigInteger(bigNum).bitLength());
		Element element = PairingUtils.mapNumStringToElement(pairing, bigNum, PairingGroupType.Zr);
		logger.info("recovered bigNum: " + PairingUtils.mapElementToNumString(element, PairingGroupType.GT));
		// 方案2 由于采用setFromHash的hash方式，不可逆
		byte[] bytes = bigNum.getBytes(StandardCharsets.UTF_8);
		Element elementGT = GT.newElementFromHash(bytes, 0, bytes.length);
		byte[] bytes2 = elementGT.toBytes();
		assertFalse(bigNum.equals(new String(bytes2, StandardCharsets.UTF_8)));
		logger.info("");
	}

	@Override
	public void setup() {
		P = G1.newRandomElement().getImmutable();// 生成G1的生成元P
		s = Zr.newRandomElement().getImmutable();// //随机生成主密钥s
		Ppub = P.mulZn(s).getImmutable();// 计算Ppub=sP,注意顺序
		logger.info("P=" + P);
		logger.info("s=" + s);
		logger.info("Ppub=" + Ppub);
	}

	@Override
	public Element keyGen(String id) {
		// 通过Hash函数G从用户IDu产生的公钥Qu
		Qu = PairingUtils.hash_G(pairing, id);
		// 通过PGK生成用户私钥
		Element d = Qu.mulZn(s).getImmutable();
		return d;
	}

	@Override
	// 注意，这里M不能过长，受到Fq2中q的大小限制
	public IBEHECipherText encrypt(String message) {
		Element r = Zr.newRandomElement().getImmutable();
		// 密文的第一部分 U = rP
		Element U = P.mulZn(r);
		// g = e(Qu,Ppub);
		Element g = this.pairing.pairing(Qu, Ppub).getImmutable();// 计算e（Ppub,Qu）
		// gr = g^r
		Element gr = g.powZn(r).getImmutable();
		// Hash_H:Fp2->{0,1}^n
		// H1 = hash_H(g^r)
		Element H1 = PairingUtils.hash_H(this.pairing, gr);
		logger.info("H1=Hash_H(e（Qu, Ppub）^r):" + H1);
		// 密文的第二部分 V = M xor H; M 是明文. 密文: C = (U, V)
		Element M = PairingUtils.mapNumStringToElement(pairing, message, PairingGroupType.GT);
		Element V = M.add(H1);
//		byte[] messageBytes = biMessage.toByteArray();
//		int byteLen = H1.getLengthInBytes();
//		Element V = PairingUtils.xor(pairing, messageBytes, H1.toBytes());
		logger.info("V                        :" + V);
		return new IBEHECipherText(U, V, r, g, gr, H1);
	}

	@Override
	public String decrypt(Element d, CipherText ciphertext) {
		ciphertext = ciphertext;
		// g2 = e(d,U)
		Element g2 = this.pairing.pairing(d, ciphertext.getU()).getImmutable();
		// 因为 g2=e(d,U)= e(sQu,rP)=e(Qu,P)^sr=e(Qu,Ppub)^r=g^r
		// H2 = hash_H(g2)
		// 则明文: M = V xor H
		Element H2 = PairingUtils.hash_H(this.pairing, g2);
		logger.info("H2=Hash_H(e(Su, U))      =" + H2);
		Element V = ciphertext.getV();
//		Element decrypte_M = PairingUtils.xor(pairing, V, H2);
//		byte[] decryptedBytes = decrypte_M.toBytes();
//		return new BigInteger(Arrays.copyOfRange(decryptedBytes, 0, decrypte_M.getLengthInBytes() / 2)).toString();
		Element decrypte_M = V.sub(H2);
		return PairingUtils.mapElementToNumString(decrypte_M, PairingGroupType.GT);
	}

	@Override
	public CipherText eval(Map<String, CipherText> ciphertextMap) {
		Element U = this.G1.newZeroElement();
		Element V = this.GT.newZeroElement();
		Element r = this.Zr.newZeroElement();
		Element g = this.GT.newZeroElement();
		Element gr = this.GT.newOneElement();
		Element H = this.GT.newZeroElement();
		for (CipherText ciphertext : ciphertextMap.values()) {
			IBEHECipherText ibeCiphertext = (IBEHECipherText) ciphertext;
			U = U.add(ibeCiphertext.getU());
			V = V.add(ibeCiphertext.getV());
			r = r.add(ibeCiphertext.getR());
			Element temp_g = ibeCiphertext.getG();
			if (g.isZero()) {
				g = temp_g;
			} else {
				assertTrue(g.isEqual(temp_g));
			}
			gr = gr.mul(ibeCiphertext.getGr());
			H = H.add(ibeCiphertext.getH());
		}
		return new IBEHECipherText(U.getImmutable(), V.getImmutable(), r.getImmutable(), g.getImmutable(),
				gr.getImmutable(), H.getImmutable());
	}

}
