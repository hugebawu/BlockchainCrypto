package com.example.utils;

import cn.edu.ncepu.crypto.utils.PairingUtils;
import cn.edu.ncepu.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

import static org.junit.Assert.assertTrue;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/4/23 14:11
 *//*
 * @ClassName PairPerformanceTest
 * @Description test performance of cryptography operation in various bilinear pairing groups
 * @Author Administrator
 * @Date 2021/4/23 14:11
 * @Version 1.0
 */
public class PairPerformanceTest {
    private static final Logger logger = LoggerFactory.getLogger(PairingUtilsTest.class);

    private Out out;
    private static final String default_path = "benchmarks/utils/"; // file path for performance test result
    private double timeExpInG1, timeMulInG1, timeMulInGT, timePairInE; // type F
    private double timeExpInG, timeMulInG, timePL; // type A1
    BigInteger n, p, q; //type A1
    Pairing pairing;
    private final int test_round = 1_000;

    @Test
    public void testTypeFPerformance() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_f_256);
        pairing = PairingFactory.getPairing(pairingParameters);
        String PAIRING_NAME = "type F prime order bilinear pairing";
        this.out = new Out(default_path + PAIRING_NAME);
        this.out.println("Test various cryptography operation of " + PAIRING_NAME);
        this.out.println("All test rounds: " + test_round);
        logger.info("All test rounds: " + test_round);
        for (int i = 0; i < test_round; i++) {
            logger.info("Test round: " + (i + 1));
            out.println("Test round: " + (i + 1));
            run_one_round_TypeF();
            logger.info("");
        }
        logger.info("average ExpInG1 time: " + timeExpInG1 / test_round);
        out.println("average ExpInG1 time: " + timeExpInG1 / test_round);
        logger.info("average MulInG1 time: " + timeMulInG1 / test_round);
        out.println("average MulInG1 time: " + timeMulInG1 / test_round);
        logger.info("average MulInGT time: " + timeMulInGT / test_round);
        out.println("average MulInGT time: " + timeMulInGT / test_round);
        logger.info("average PairInE time: " + timePairInE / test_round);
        out.println("average PairInE time: " + timePairInE / test_round);
    }

    private void run_one_round_TypeF() {
        Element g1, g2, gt, x;
        g1 = pairing.getG1().newRandomElement().getImmutable();
        g2 = pairing.getG2().newRandomElement().getImmutable();
        gt = pairing.pairing(g1, g2).getImmutable();
        x = pairing.getZr().newRandomElement().getImmutable();

        double tempTime;
        Timer timer = new Timer();
        timer.setFormat(0, Timer.FORMAT.MICRO_SECOND); //设置以微秒为单位

        //test performance of exponential operation in G1
        out.print("expInG1:");
        timer.start(0);
        g1.powZn(x);
        tempTime = timer.stop(0);
        logger.info("expInG1:" + "\t" + tempTime);
        out.println("\t" + tempTime);
        this.timeExpInG1 += tempTime;

        //test performance of multiplicative operation in G1
        out.print("mulInG1:");
        timer.start(0);
        g1.mul(g1);
        tempTime = timer.stop(0);
        logger.info("mulInG1:" + "\t" + tempTime);
        out.println("\t" + tempTime);
        this.timeMulInG1 += tempTime;

        //test performance of multiplicative operation in GT
        out.print("mulInGT:");
        timer.start(0);
        gt.mul(gt);
        tempTime = timer.stop(0);
        logger.info("mulInGT:" + "\t" + tempTime);
        out.println("\t" + tempTime);
        this.timeMulInGT += tempTime;

        //test performance of pairing operation in e
        out.print("PairInE:");
        timer.start(0);
        pairing.pairing(g1, g2);
        tempTime = timer.stop(0);
        logger.info("PairInE:" + "\t" + tempTime);
        out.println("\t" + tempTime);
        this.timePairInE += tempTime;
    }

    @Test
    public void testTypeA1Performance() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a1_2_256);
        pairing = PairingFactory.getPairing(pairingParameters);
        n = pairingParameters.getBigInteger("n");
        p = pairingParameters.getBigInteger("n0");
        q = pairingParameters.getBigInteger("n1");
        String PAIRING_NAME = "type A1 composite order bilinear pairing";
        this.out = new Out(default_path + PAIRING_NAME);
        this.out.println("Test various cryptography operation of " + PAIRING_NAME);
        this.out.println("All test rounds: " + test_round);
        logger.info("All test rounds: " + test_round);
        for (int i = 0; i < test_round; i++) {
            logger.info("Test round: " + (i + 1));
            out.println("Test round: " + (i + 1));
            run_one_round_TypeA1();
            logger.info("");
        }
        logger.info("average ExpInG time: " + timeExpInG / test_round);
        out.println("average ExpInG time: " + timeExpInG / test_round);
        logger.info("average MulInG time: " + timeMulInG / test_round);
        out.println("average MulInG time: " + timeMulInG / test_round);
        logger.info("average PL time: " + timePL / test_round);
        out.println("average PL time: " + timePL / test_round);
    }

    private void run_one_round_TypeA1() {
        Element g, u, h, r;
        g = pairing.getG1().newRandomElement().getImmutable();
        u = pairing.getG2().newRandomElement().getImmutable();
        h = u.pow(q);
        r = pairing.getZr().newRandomElement().getImmutable();
        int M = 100, m = M;

        double tempTime;
        Timer timer = new Timer();
        timer.setFormat(0, Timer.FORMAT.MICRO_SECOND); //设置以微秒为单位

        //test performance of exponential operation in G
        out.print("expInG:");
        timer.start(0);
        g.powZn(r);
        tempTime = timer.stop(0);
        logger.info("expInG:" + "\t" + tempTime);
        out.println("\t" + tempTime);
        this.timeExpInG += tempTime;

        //test performance of multiplicative operation in G
        out.print("mulInG:");
        timer.start(0);
        g.mul(g);
        tempTime = timer.stop(0);
        logger.info("mulInG:" + "\t" + tempTime);
        out.println("\t" + tempTime);
        this.timeMulInG += tempTime;

        //test performance of Pollard’s Lamda Method
        out.print("Pollard's Lamda:");
        Element c = g.pow(BigInteger.valueOf(m)).mul(h.powZn(r));
        Element cp = c.pow(p).getImmutable();
        Element gp = g.pow(p).getImmutable();
        timer.start(0);
        int i = 0;
        for (; i <= M; i++) {
            if (gp.pow(BigInteger.valueOf(i)).isEqual(cp)) {
                break;
            }
        }
        tempTime = timer.stop(0);
        assertTrue(i == m);
        logger.info("Pollard's Lamda:" + "\t" + tempTime);
        out.println("\t" + tempTime);
        this.timePL += tempTime;
    }
}
