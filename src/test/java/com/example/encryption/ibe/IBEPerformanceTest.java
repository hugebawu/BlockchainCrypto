package com.example.encryption.ibe;

import cn.edu.ncepu.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.encryption.ibe.IBEEngine;
import cn.edu.ncepu.crypto.encryption.ibe.bf01a.IBEBF01aEngine;
import cn.edu.ncepu.crypto.encryption.ibe.gen06a.IBEGen06aEngine;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Weiran Liu on 2016/12/5.
 *
 * Generic IBE performance test.
 */
public class IBEPerformanceTest {
	private static final Logger logger = LoggerFactory.getLogger(IBEPerformanceTest.class);
	private String pairingParameterPath;
	// file path for performance test result
	private static final String default_path = "benchmarks/encryption/ibe/";
	// test round
	private int test_round;
	// setup time
	private double timeSetup;
	// identity
	private String identity;
	// secret key generation time
	private double timeKeyGen;

	// key encapsulation time
	private double timeEncapsulation;
	private double timeEncryption;

	// decapsulation time
	private double timeDecapsulation;
	private double timeDecryption;

	private IBEEngine engine;

	private Out out;

	private void init() {
		this.identity = "ID";
	}

	private void runPerformanceTest() {
		out = new Out(default_path + engine.getEngineName());
		out.println("Test IBE engine: " + engine.getEngineName());
		out.println("All test rounds: " + this.test_round);

		for (int i = 0; i < test_round; i++) {
			logger.info("Test round: " + (i + 1));
			out.println("Test round: " + (i + 1));
			run_one_round();
		}
		out.println();
		out.println("Final performance test:");
		// write results to the file
		// write setup time
		out.print("Setup : ");
		out.println("\t" + this.timeSetup / test_round);

		// write KeyGen
		out.print("KeyGen: ");
		out.println("\t" + this.timeKeyGen / test_round);

		// write encapsulation
		out.print("Encapsulation: ");
		out.println("\t" + this.timeEncapsulation / test_round);

		// write encrption
		out.print("Encryption: ");
		out.println("\t" + this.timeEncryption / test_round);

		// write decapsulation
		out.print("Decapsulation: ");
		out.println("\t" + this.timeDecapsulation / test_round);

		// write decryption
		out.print("Decryption: ");
		out.println("\t" + this.timeDecryption / test_round);
	}

	private void run_one_round() {
		try {
			PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParameterPath);
			Pairing pairing = PairingFactory.getPairing(pairingParameters);

			double temperTime;
			Timer timer = new Timer();
			// test setup performance
			out.print("Setup : ");
			timer.start(0);
			PairingKeySerPair keyPair = engine.setup(pairingParameters);
			temperTime = timer.stop(0);

			logger.info("Setup; " + "\t" + temperTime);
			out.println("\t" + temperTime);
			this.timeSetup += temperTime;

			PairingKeySerParameter publicKey = keyPair.getPublic();
			PairingKeySerParameter masterKey = keyPair.getPrivate();

			// test secret key generation performance
			out.print("KeyGen: ");
			timer.start(0);
			PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identity);
			temperTime = timer.stop(0);
			logger.info("KeyGen;" + "\t" + temperTime);
			out.println("\t" + temperTime);
			this.timeKeyGen += temperTime;

			// test encapsulation performance
			out.print("Encapsulation: ");
			timer.start(0);
			PairingCipherSerParameter header = engine.encapsulation(publicKey, identity).getHeader();
			temperTime = timer.stop(0);
			logger.info("Encapsulation; " + "\t" + temperTime);
			out.println("\t" + temperTime);
			this.timeEncapsulation += temperTime;

			// test encryption performance
			out.print("Encryption: ");
			Element message = pairing.getGT().newRandomElement().getImmutable();
			timer.start(0);
			PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identity, message);
			temperTime = timer.stop(0);
			logger.info("Encryption; " + "\t" + temperTime);
			out.println("\t" + temperTime);
			this.timeEncryption += temperTime;

			// test decapsulation performance
			out.print("Decapsulation: ");
			timer.start(0);
			engine.decapsulation(publicKey, secretKey, identity, header);
			temperTime = timer.stop(0);
			logger.info("Decapsulation; " + "\t" + temperTime);
			out.println("\t" + temperTime);
			this.timeDecapsulation += temperTime;

			// test decryption performance
			out.print("Decryption: ");
			timer.start(0);
			engine.decryption(publicKey, secretKey, identity, ciphertext);
			temperTime = timer.stop(0);
			logger.info("Decryption; " + "\t" + temperTime);
			out.println("\t" + temperTime);
			this.timeDecryption += temperTime;
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}
	}

	@Ignore
	@Test
	public void testBF01aPerformance() {
		IBEPerformanceTest performanceTest = new IBEPerformanceTest();
		performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
		performanceTest.test_round = PairingUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
		performanceTest.engine = IBEBF01aEngine.getInstance();
		performanceTest.init();
		performanceTest.runPerformanceTest();
	}

	@Ignore
	@Test
	public void testGen06aPerformance() {
		IBEPerformanceTest performanceTest = new IBEPerformanceTest();
		performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
		performanceTest.test_round = PairingUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
		performanceTest.engine = IBEGen06aEngine.getInstance();
		performanceTest.init();
		performanceTest.runPerformanceTest();
	}
}
