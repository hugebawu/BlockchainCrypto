/**
 * 
 */
package cn.edu.ncepu.crypto.encryption.ecceg;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.edu.ncepu.crypto.algebra.Engine;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;

/**
 * @Copyright : Copyright (c) 2020-2021 E1101智能电网信息安全中心
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @CreateData: Jul 14, 2020 4:04:40 PM
 * @ClassName ECCEGEngine
 * @Description:  (这里用一句话描述这个方法的作用)
 */
@SuppressWarnings("rawtypes")
public class ECCEGEngine extends Engine {
	private static Logger logger = LoggerFactory.getLogger(ECCEGEngine.class);
	private static final String SCHEME_NAME = "ecliptic curve cryptography based elgamal encryption scheme";
	private static ECCEGEngine engine;

	public static ECCEGEngine getInstance() {
		if (engine == null) {
			engine = new ECCEGEngine();
		}
		return engine;
	}

	Pairing pairing;
	CurveField curveField;
	ZrField zrField;
	CurveElement P;

	private ECCEGEngine() {
		super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.ANON);
	}

	public void setup(Pairing pairing) {
		this.pairing = pairing;
		curveField = (CurveField) pairing.getG1();
		P = (CurveElement) curveField.newRandomElement().getImmutable();
	}

	public ECCEGKeyPair extract() {
		zrField = (ZrField) pairing.getZr();
		ZrElement privateKey = (ZrElement) zrField.newRandomElement().getImmutable();
		CurveElement publickKey = (CurveElement) P.mulZn(privateKey).getImmutable();
		return new ECCEGKeyPair(privateKey, publickKey);
	}

	public ECCEGCipherText encrypt(CurveElement M, CurveElement publicKey) {
		ZrElement r = (ZrElement) zrField.newRandomElement().getImmutable();
		CurveElement U = (CurveElement) P.mulZn(r).getImmutable();
		CurveElement rQ = (CurveElement) publicKey.mulZn(r).getImmutable();
		logger.info("rQ:" + rQ);
		CurveElement V = (CurveElement) M.add(rQ).getImmutable();
		if (!U.isValid() || !V.isValid()) {
			throw new IllegalStateException("curve element is invalid");
		}
		return new ECCEGCipherText(U, V, r);
	}

	public CurveElement decrypt(ECCEGCipherText cipherText, ZrElement privateKey) {
		CurveElement U = cipherText.getU();
		CurveElement V = cipherText.getV();
		CurveElement dU = U.mulZn(privateKey);
		logger.info("dU:" + dU);
		CurveElement decrypted_M = (CurveElement) V.sub(dU).getImmutable();
		return decrypted_M;
	}

	public ECCEGCipherText add(List<ECCEGCipherText> cipherTextList) {
		CurveElement U = (CurveElement) curveField.newZeroElement();
		CurveElement V = (CurveElement) curveField.newZeroElement();
		ZrElement r = zrField.newZeroElement();

		for (ECCEGCipherText cihpertext : cipherTextList) {
			U = U.add(cihpertext.getU());
			V = V.add(cihpertext.getV());
			r = r.add(cihpertext.getR());
		}
		if (!U.isValid() || !V.isValid()) {
			throw new IllegalStateException("curve element is invalid");
		}
		logger.info("added U:" + U);
		logger.info("added V:" + V);
		logger.info("added r:" + r);
		return new ECCEGCipherText(U, V, r);
	}

	public static String getSchemeName() {
		return SCHEME_NAME;
	}

	public CurveField getCurveField() {
		return curveField;
	}

	public ZrField getZrField() {
		return zrField;
	}

	public CurveElement getP() {
		return (CurveElement) P.getImmutable();
	}

}
