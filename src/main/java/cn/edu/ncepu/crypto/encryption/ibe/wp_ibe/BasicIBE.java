/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.ibe.wp_ibe;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.PairingUtils.PairingGroupType;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import it.unisa.dia.gas.plaf.jpbc.field.quadratic.DegreeTwoExtensionQuadraticField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeAPairing;

/**
 *
 * @版权 : Copyright (c) 2018-2019 E1101智能电网信息安全中心
 * @author: Hu Baiji
 * @E-mail: drbjhu@163.com
 * @创建日期: 2019年10月16日 下午7:37:14
 * @ClassName BasicIdent2
 * @类描述-Description:  这个类是核心类，包括初始化init()，配对的对称性判断checkSymmetric()，
 * 系统建立buildSystem()，密钥提取extractSecretKey()，加密encrypt()，解密decrypt()。
 * @修改记录:
 * @版本: 1.0
 */

public class BasicIBE implements IBE {
	private static Logger logger = LoggerFactory.getLogger(BasicIBE.class);
	// system parameters: params = <q,n,P,Ppub,G,H>
	private Element s, // master key
			P, // G1的生成元
			Ppub, // Ppub = sP
			Qu; // 用户公钥 Qu = hash_G("User ID")
	private TypeAPairing pairing;
	// G1是定义在域Fq上的椭圆曲线，其阶为r.q与r都是质数，且存在一定的关系：这里是 (q+1)=r*h
	// Zr 是阶为r的环Zr={0,...,r-1}
	// GT是有限域Fq2。其元素的阶虽然为r，但是其取值范围比q大的多，目前不清楚怎么回事。
	private ZrField Zr;
	private CurveField<ZrField> G1;
	private GTFiniteField<DegreeTwoExtensionQuadraticField<ZrField>> GT;

	public BasicIBE(PairingParameters typeAParams) {
		this.pairing = (TypeAPairing) PairingFactory.getPairing(typeAParams);
		// For bilinear maps only, to use the PBC wrapper and gain in performance, the
		// usePBCWhenPossible property of the pairing factory must be set.
		// Moreover, if PBC and the JPBC wrapper are not installed properly then the
		// factory will resort to the JPBC pairing implementation.
		// 需要配置才能使用http://gas.dia.unisa.it/projects/jpbc/docs/pbcwrapper.html#.XvnxeygzZPY
		PairingFactory.getInstance().setUsePBCWhenPossible(true);//
		checkSymmetric(pairing);
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
		logger.info("recovered bigNum: " + PairingUtils.mapElementToNumString(element));
		// 方案2 由于采用setFromHash的hash方式，不可逆
		try {
			byte[] bytes = bigNum.getBytes("UTF-8");
			Element elementGT = GT.newElementFromHash(bytes, 0, bytes.length);
			byte[] bytes2 = elementGT.toBytes();
			assertFalse(bigNum.equals(new String(bytes2, "UTF-8")));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		logger.info("");
	}

	public class CipherText {

		// U = rP
		private Element U;
		// V = M.xor(H.toBigInter())
		private Element V;
		private Element r;
		private Element g;
		// gr = g^r
		private Element gr;
		// H = hash_H(gr)
		private Element H;

		CipherText(Element U, Element V, Element r, Element g, Element gr, Element H) {
			this.U = U.getImmutable();
			this.V = V.getImmutable();
			this.r = r.getImmutable();
			this.g = g.getImmutable();
			this.gr = gr.getImmutable();
			this.H = H.getImmutable();
		}

		@Override
		public boolean equals(Object object) {
			if (this == object) {
				return true;
			}
			if (object instanceof CipherText) {
				CipherText that = (CipherText) object;
				return (this.U.isEqual(that.U)) && (this.V.isEqual(that.V)) && (this.r.isEqual(that.r))
						&& (this.g.isEqual(that.g)) && (this.gr.isEqual(that.gr)) && (this.H.isEqual(that.H));
			}
			return false;
		}

		public Element getU() {
			return U.duplicate();
		}

		public Element getV() {
			return V.duplicate();
		}

		public Element getR() {
			return r.duplicate();
		}

		public Element getG() {
			return g.duplicate();
		}

		public Element getGr() {
			return gr.duplicate();
		}

		public Element getH() {
			return H.duplicate();
		}
	}

	/**
	 * 判断配对是否为对称配对，不对称则输出错误信息
	 * @param pairing 
	 * @return void  
	 */
	private void checkSymmetric(Pairing pairing) {
		if (!pairing.isSymmetric()) {
			throw new RuntimeException("密钥不对称!");
		}
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
	public Element extract(String id) {
		// 通过Hash函数G从用户IDu产生的公钥Qu
		Qu = PairingUtils.hash_G(pairing, id);
		// 通过PGK生成用户私钥
		Element d = Qu.mulZn(s).getImmutable();
		return d;
	}

	@Override
	// 注意，这里M不能过长，受到Fq2中q的大小限制
	public CipherText encrypt(String message) {
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
		return new CipherText(U, V, r, g, gr, H1);
	}

	@Override
	public String decrypt(Element d, CipherText ciphertext) {
		// g2 = e(d,U)
		Element g2 = this.pairing.pairing(d, ciphertext.getU()).getImmutable();
		// 因为 g2=e(d,U)= e(sQu,rP)=e(Qu,P)^sr=e(Qu,Ppub)^r=g^r
		// H2 = hash_H(g2)
		// 则明文: M = V xor H
		Element H2 = PairingUtils.hash_H(this.pairing, g2);
		logger.info("H2=Hash_H(e(Su, U))      =" + H2);
		Element V = ciphertext.V;
//		Element decrypte_M = PairingUtils.xor(pairing, V, H2);
//		byte[] decryptedBytes = decrypte_M.toBytes();
//		return new BigInteger(Arrays.copyOfRange(decryptedBytes, 0, decrypte_M.getLengthInBytes() / 2)).toString();
		Element decrypte_M = V.sub(H2);
		return PairingUtils.mapElementToNumString(decrypte_M);
	}

	@Override
	public CipherText add(Map<String, CipherText> ciphertextMap) {
		Element U = this.G1.newZeroElement();
		Element V = this.GT.newZeroElement();
		Element r = this.Zr.newZeroElement();
		Element g = this.GT.newZeroElement();
		Element gr = this.GT.newOneElement();
		Element H = this.GT.newZeroElement();
		for (CipherText ciphertext : ciphertextMap.values()) {
			U = U.add(ciphertext.getU());
			V = V.add(ciphertext.getV());
			r = r.add(ciphertext.getR());
			Element temp_g = ciphertext.getG();
			if (g.isZero()) {
				g = temp_g;
			} else {
				assertTrue(g.isEqual(temp_g));
			}
			gr = gr.mul(ciphertext.getGr());
			H = H.add(ciphertext.getH());
		}
		return new CipherText(U.getImmutable(), V.getImmutable(), r.getImmutable(), g.getImmutable(), gr.getImmutable(),
				H.getImmutable());
	}

}
